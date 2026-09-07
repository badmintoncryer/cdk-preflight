package cdk_preflight

import rego.v1

# EventBridge Scheduler validates ScheduleExpression itself; the engine's
# E3027 only covers AWS::Events::Rule, so nothing checks this property.
# Grammar measured 2026-09-07 against scheduler:CreateSchedule in us-east-1.
# Only defects that were observed to be rejected are reported here; notably
# rate() does NOT enforce singular/plural agreement, a 5-field cron is
# accepted, and the L / W / <dow>L modifiers are all valid. A rate value
# of zero is left to pf-scheduler-rate-positive.
_pf_schexpr_url := "https://docs.aws.amazon.com/scheduler/latest/UserGuide/schedule-types.html"

_pf_schexpr_raw(name) := e if {
	e := resolve(name, "Properties.ScheduleExpression")
	is_string(e)
}

# Keywords are case-insensitive ("AT(...)" deploys), the body is not.
_pf_schexpr_body(e, kw) := substring(e, count(kw) + 1, count(e) - count(kw) - 2) if {
	startswith(lower(e), concat("", [kw, "("]))
	endswith(e, ")")
}

_pf_schexpr_rate_units := {"minute", "minutes", "hour", "hours", "day", "days"}

_pf_schexpr_rate_parts(b) := m[0] if {
	m := regex.find_all_string_submatch_n(`^([0-9]+) *([a-z]+)$`, lower(b), 1)
	count(m) == 1
}

violation contains make_diag_full("pf-scheduler-schedule-expression", "ERROR", name,
	"Properties.ScheduleExpression",
	sprintf("rate() takes a positive integer and a unit; CreateSchedule rejects '%s' with \"Invalid Schedule Expression %s\"", [e, e]),
	"Write rate(<positive integer> <minute(s)|hour(s)|day(s)>)",
	_pf_schexpr_url) if {
	some name in resources_of_type("AWS::Scheduler::Schedule")
	e := _pf_schexpr_raw(name)
	b := _pf_schexpr_body(e, "rate")
	not _pf_schexpr_rate_parts(b)
}

violation contains make_diag_full("pf-scheduler-schedule-expression", "ERROR", name,
	"Properties.ScheduleExpression",
	sprintf("rate() unit '%s' is not supported; CreateSchedule rejects '%s' with \"Invalid Schedule Expression %s\"", [p[2], e, e]),
	"Use minute(s), hour(s) or day(s)",
	_pf_schexpr_url) if {
	some name in resources_of_type("AWS::Scheduler::Schedule")
	e := _pf_schexpr_raw(name)
	p := _pf_schexpr_rate_parts(_pf_schexpr_body(e, "rate"))
	not p[2] in _pf_schexpr_rate_units
}

# --- cron() -------------------------------------------------------------
# minute hour day-of-month month day-of-week [year]; 4 and 7 fields are
# rejected, 5 and 6 are accepted.
_pf_schexpr_cron_fields(e) := f if {
	b := _pf_schexpr_body(e, "cron")
	f := split(b, " ")
	every x in f {
		count(x) > 0
	}
}

_pf_schexpr_ranges := {0: [0, 59], 1: [0, 23], 2: [1, 31], 3: [1, 12], 4: [1, 7]}

violation contains make_diag_full("pf-scheduler-schedule-expression", "ERROR", name,
	"Properties.ScheduleExpression",
	sprintf("cron() takes 5 or 6 fields but '%s' has %d; CreateSchedule rejects it with \"Invalid Schedule Expression %s\"", [e, count(f), e]),
	"Write cron(minute hour day-of-month month day-of-week [year])",
	_pf_schexpr_url) if {
	some name in resources_of_type("AWS::Scheduler::Schedule")
	e := _pf_schexpr_raw(name)
	f := _pf_schexpr_cron_fields(e)
	not count(f) in {5, 6}
}

violation contains make_diag_full("pf-scheduler-schedule-expression", "ERROR", name,
	"Properties.ScheduleExpression",
	sprintf("cron() requires '?' in exactly one of day-of-month and day-of-week, but '%s' has '%s' and '%s'; CreateSchedule rejects it with \"Invalid Schedule Expression %s\"", [e, f[2], f[4], e]),
	"Put '?' in whichever of day-of-month / day-of-week you are not specifying",
	_pf_schexpr_url) if {
	some name in resources_of_type("AWS::Scheduler::Schedule")
	e := _pf_schexpr_raw(name)
	f := _pf_schexpr_cron_fields(e)
	count(f) in {5, 6}
	count({i | some i in [2, 4]; f[i] == "?"}) != 1
}

violation contains make_diag_full("pf-scheduler-schedule-expression", "ERROR", name,
	"Properties.ScheduleExpression",
	sprintf("cron() field %d is '%s', outside the allowed %d-%d; CreateSchedule rejects '%s' with \"Invalid Schedule Expression %s\"", [i + 1, f[i], r[0], r[1], e, e]),
	"Use a value inside the field's range",
	_pf_schexpr_url) if {
	some name in resources_of_type("AWS::Scheduler::Schedule")
	e := _pf_schexpr_raw(name)
	f := _pf_schexpr_cron_fields(e)
	count(f) in {5, 6}
	some i, r in _pf_schexpr_ranges
	v := to_number(f[i])
	not _pf_schexpr_in_range(v, r)
}

_pf_schexpr_in_range(v, r) if {
	v >= r[0]
	v <= r[1]
}

violation contains make_diag_full("pf-scheduler-schedule-expression", "ERROR", name,
	"Properties.ScheduleExpression",
	sprintf("cron() day-of-week '#%s' must select the 1st-5th occurrence; CreateSchedule rejects '%s' with \"Invalid Schedule Expression %s\"", [n[1], e, e]),
	"Use #1 through #5",
	_pf_schexpr_url) if {
	some name in resources_of_type("AWS::Scheduler::Schedule")
	e := _pf_schexpr_raw(name)
	f := _pf_schexpr_cron_fields(e)
	count(f) in {5, 6}
	some n in regex.find_all_string_submatch_n(`#([0-9]+)`, f[4], -1)
	not _pf_schexpr_in_range(to_number(n[1]), [1, 5])
}

# --- at() ---------------------------------------------------------------
# yyyy-mm-ddThh:mm[:ss] in the schedule's own timezone. A 'Z' or offset
# suffix, a space separator and fractional seconds are all rejected.
violation contains make_diag_full("pf-scheduler-schedule-expression", "ERROR", name,
	"Properties.ScheduleExpression",
	sprintf("at() takes yyyy-mm-ddThh:mm:ss with no timezone suffix; CreateSchedule rejects '%s' with \"Invalid Schedule Expression %s\"", [e, e]),
	"Write at(2030-01-01T00:00:00) and set the zone in ScheduleExpressionTimezone",
	_pf_schexpr_url) if {
	some name in resources_of_type("AWS::Scheduler::Schedule")
	e := _pf_schexpr_raw(name)
	b := _pf_schexpr_body(e, "at")
	not regex.match(`^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9](:[0-5][0-9])?$`, b)
}
