package cdk_preflight

import rego.v1

# The engine's E3027 already covers rate() and the cron() basics for
# AWS::Events::Rule, but two holes were measured on 2026-09-07 via
# events:PutRule in us-east-1 and confirmed to pass the bare engine: a '#'
# outside day-of-week, and a numeric field outside its range. Both give
# "Parameter ScheduleExpression is not valid." The year field is NOT checked
# here: cron(0 20 * * ? 2500) deploys, so the documented 1970-2199 range is
# not enforced (BROKEN-EXPECTATION).
_pf_evcron_url := "https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-create-rule-schedule.html"

_pf_evcron_fields(name) := f if {
	e := resolve(name, "Properties.ScheduleExpression")
	is_string(e)
	startswith(lower(e), "cron(")
	endswith(e, ")")
	f := split(substring(e, 5, count(e) - 6), " ")
	count(f) == 6
	every x in f {
		count(x) > 0
	}
}

_pf_evcron_ranges := {0: [0, 59], 1: [0, 23], 2: [1, 31], 3: [1, 12], 4: [1, 7]}

_pf_evcron_in_range(v, r) if {
	v >= r[0]
	v <= r[1]
}

violation contains make_diag_full("pf-events-rule-cron-fields", "ERROR", name,
	"Properties.ScheduleExpression",
	sprintf("'#' selects the nth weekday and only belongs in the day-of-week field, but it appears in field %d ('%s'); PutRule fails with \"Parameter ScheduleExpression is not valid\"", [i + 1, f[i]]),
	"Move the # expression into the day-of-week field",
	_pf_evcron_url) if {
	some name in resources_of_type("AWS::Events::Rule")
	f := _pf_evcron_fields(name)
	some i in [0, 1, 2, 3, 5]
	contains(f[i], "#")
}

violation contains make_diag_full("pf-events-rule-cron-fields", "ERROR", name,
	"Properties.ScheduleExpression",
	sprintf("cron() field %d is '%s', outside the allowed %d-%d; PutRule fails with \"Parameter ScheduleExpression is not valid\"", [i + 1, f[i], r[0], r[1]]),
	"Use a value inside the field's range",
	_pf_evcron_url) if {
	some name in resources_of_type("AWS::Events::Rule")
	f := _pf_evcron_fields(name)
	some i, r in _pf_evcron_ranges
	v := to_number(f[i])
	not _pf_evcron_in_range(v, r)
}
