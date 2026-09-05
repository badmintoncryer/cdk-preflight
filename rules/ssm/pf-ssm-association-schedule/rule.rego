package cdk_preflight

import rego.v1

_pf_ssmas_url := "https://docs.aws.amazon.com/systems-manager/latest/userguide/reference-cron-and-rate-expressions.html"

_pf_ssmas_fix := "Use rate(30 minutes)..rate(30 days), cron(0 0/4 * * ? *), cron(0 8 ? * MON *) or cron(0 0 ? * TUE#3 *) style expressions; set ApplyOnlyAtCronInterval for at() and offsets"

_pf_ssmas_props(name) := props if {
	props := input.resources[name].properties
	is_object(props)
}

_pf_ssmas_expr(name) := s if {
	s := resolve(name, "Properties.ScheduleExpression")
	is_string(s)
}

_pf_ssmas_apply(name) if resolve(name, "Properties.ApplyOnlyAtCronInterval") in {true, "true"}

_pf_ssmas_kind(s) := "rate" if startswith(s, "rate(")

_pf_ssmas_kind(s) := "cron" if startswith(s, "cron(")

_pf_ssmas_kind(s) := "at" if startswith(s, "at(")

violation contains make_diag_full("pf-ssm-association-schedule", "ERROR", name,
	"Properties.ScheduleExpression",
	sprintf("'%s' is not a rate(), cron() or at() expression; CreateAssociation fails with \"Only schedule expressions of type rate, cron, and at are supported.\"", [s]),
	_pf_ssmas_fix, _pf_ssmas_url) if {
	some name in resources_of_type("AWS::SSM::Association")
	s := _pf_ssmas_expr(name)
	not _pf_ssmas_kind(s)
}

_pf_ssmas_rate(s) := [to_number(m[0][1]), m[0][2]] if {
	m := regex.find_all_string_submatch_n("^rate\\(([0-9]+) (minute|minutes|hour|hours|day|days)\\)$", s, 1)
	count(m) == 1
}

violation contains make_diag_full("pf-ssm-association-schedule", "ERROR", name,
	"Properties.ScheduleExpression",
	sprintf("'%s' is not rate(N minute(s)|hour(s)|day(s)); CreateAssociation fails with \"is not a valid rate expression. Supported examples are: rate(30 minutes), rate(2 hours) and rate(5 days).\"", [s]),
	_pf_ssmas_fix, _pf_ssmas_url) if {
	some name in resources_of_type("AWS::SSM::Association")
	s := _pf_ssmas_expr(name)
	_pf_ssmas_kind(s) == "rate"
	not _pf_ssmas_rate(s)
}

violation contains make_diag_full("pf-ssm-association-schedule", "ERROR", name,
	"Properties.ScheduleExpression",
	sprintf("'%s' mixes a value of %d with the unit '%s' (1 takes the singular, anything else the plural); CreateAssociation fails with \"is not a valid rate expression\"", [s, n, unit]),
	_pf_ssmas_fix, _pf_ssmas_url) if {
	some name in resources_of_type("AWS::SSM::Association")
	s := _pf_ssmas_expr(name)
	[n, unit] := _pf_ssmas_rate(s)
	_pf_ssmas_plural_mismatch(n, unit)
}

_pf_ssmas_plural_mismatch(n, unit) if {
	n == 1
	endswith(unit, "s")
}

_pf_ssmas_plural_mismatch(n, unit) if {
	n != 1
	not endswith(unit, "s")
}

violation contains make_diag_full("pf-ssm-association-schedule", "ERROR", name,
	"Properties.ScheduleExpression",
	sprintf("'%s' runs more often than every 30 minutes; CreateAssociation fails with \"Minimum interval for rate based association is 30 minutes.\"", [s]),
	_pf_ssmas_fix, _pf_ssmas_url) if {
	some name in resources_of_type("AWS::SSM::Association")
	s := _pf_ssmas_expr(name)
	[n, unit] := _pf_ssmas_rate(s)
	startswith(unit, "minute")
	n < 30
}

violation contains make_diag_full("pf-ssm-association-schedule", "ERROR", name,
	"Properties.ScheduleExpression",
	sprintf("'%s' is an at() schedule, which needs ApplyOnlyAtCronInterval: true; CreateAssociation fails with \"At Schedule Expression must be used with ApplyOnlyAtCronInterval = true\"", [s]),
	_pf_ssmas_fix, _pf_ssmas_url) if {
	some name in resources_of_type("AWS::SSM::Association")
	s := _pf_ssmas_expr(name)
	_pf_ssmas_kind(s) == "at"
	not _pf_ssmas_apply(name)
}

violation contains make_diag_full("pf-ssm-association-schedule", "ERROR", name,
	"Properties.ScheduleExpression",
	sprintf("'%s' is not at(yyyy-MM-ddTHH:mm[:ss]) without a time zone suffix; CreateAssociation fails with \"Invalid schedule at DateTime expression\"", [s]),
	_pf_ssmas_fix, _pf_ssmas_url) if {
	some name in resources_of_type("AWS::SSM::Association")
	s := _pf_ssmas_expr(name)
	_pf_ssmas_kind(s) == "at"
	not regex.match("^at\\([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}(:[0-9]{2})?\\)$", s)
}

# cron(): min hour dom month dow year (optionally preceded by seconds)
_pf_ssmas_fields(s) := f if {
	endswith(s, ")")
	f := [x | some x in split(substring(s, 5, count(s) - 6), " "); x != ""]
	count(f) >= 6
}

_pf_ssmas_six(f) := f if count(f) == 6

_pf_ssmas_six(f) := array.slice(f, 1, 7) if count(f) == 7

_pf_ssmas_f7(name) := _pf_ssmas_fields(_pf_ssmas_expr(name))

_pf_ssmas_f6(name) := _pf_ssmas_six(_pf_ssmas_f7(name))

# one [name, reason] per failed cron check
_pf_ssmas_bad contains [name, "the seconds field must be 0"] if {
	some name in resources_of_type("AWS::SSM::Association")
	f7 := _pf_ssmas_f7(name)
	count(f7) == 7
	f7[0] != "0"
}

_pf_ssmas_bad contains [name, "the year field must be *"] if {
	some name in resources_of_type("AWS::SSM::Association")
	f := _pf_ssmas_f6(name)
	f[5] != "*"
}

_pf_ssmas_bad contains [name, "months cannot be specified (the month field must be *)"] if {
	some name in resources_of_type("AWS::SSM::Association")
	f := _pf_ssmas_f6(name)
	f[3] != "*"
}

_pf_ssmas_bad contains [name, "day-of-month values are not accepted (use *, ? or 1/1)"] if {
	some name in resources_of_type("AWS::SSM::Association")
	f := _pf_ssmas_f6(name)
	not f[2] in ["*", "?", "1/1"]
}

_pf_ssmas_bad contains [name, "day-of-week lists and ranges are not accepted (a single day, *, ?, DAY#n or DAYL)"] if {
	some name in resources_of_type("AWS::SSM::Association")
	f := _pf_ssmas_f6(name)
	regex.match("[,-]", f[4])
}

_pf_ssmas_bad contains [name, "day-of-month must be ? when a day-of-week is given"] if {
	some name in resources_of_type("AWS::SSM::Association")
	f := _pf_ssmas_f6(name)
	not f[4] in ["*", "?"]
	f[2] != "?"
}

_pf_ssmas_bad contains [name, "exactly one of day-of-month and day-of-week must be ?"] if {
	some name in resources_of_type("AWS::SSM::Association")
	f := _pf_ssmas_f6(name)
	f[2] == "?"
	f[4] == "?"
}

_pf_ssmas_bad contains [name, "exactly one of day-of-month and day-of-week must be ?"] if {
	some name in resources_of_type("AWS::SSM::Association")
	f := _pf_ssmas_f6(name)
	f[2] != "?"
	f[4] != "?"
}

_pf_ssmas_bad contains [name, "minutes must be a fixed minute or 0/30"] if {
	some name in resources_of_type("AWS::SSM::Association")
	f := _pf_ssmas_f6(name)
	not _pf_ssmas_minutes_ok(f[0])
}

_pf_ssmas_minutes_ok(m) if regex.match("^[0-5]?[0-9]$", m)

_pf_ssmas_minutes_ok(m) if m == "0/30"

_pf_ssmas_bad contains [name, "hours must be a fixed hour, 0/1, 0/2, 0/4, 0/8, 0/12 or 0/24 (or * with 0/30 minutes)"] if {
	some name in resources_of_type("AWS::SSM::Association")
	f := _pf_ssmas_f6(name)
	not _pf_ssmas_hours_ok(f[1], f[0])
}

_pf_ssmas_hours_ok(h, _) if regex.match("^([01]?[0-9]|2[0-3])$", h)

_pf_ssmas_hours_ok(h, m) if {
	h == "*"
	m == "0/30"
}

_pf_ssmas_hours_ok(h, _) if h in ["0/1", "0/2", "0/4", "0/8", "0/12", "0/24"]

_pf_ssmas_bad contains [name, "an hourly interval (0/N) cannot be combined with a specific day-of-week"] if {
	some name in resources_of_type("AWS::SSM::Association")
	f := _pf_ssmas_f6(name)
	contains(f[1], "/")
	not f[4] in ["*", "?"]
}

_pf_ssmas_bad contains [name, "#n must select the 1st..5th weekday"] if {
	some name in resources_of_type("AWS::SSM::Association")
	f := _pf_ssmas_f6(name)
	some m in regex.find_all_string_submatch_n("#([0-9]+)", f[4], -1)
	to_number(m[1]) > 5
}

violation contains make_diag_full("pf-ssm-association-schedule", "ERROR", name,
	"Properties.ScheduleExpression",
	sprintf("'%s': %s; CreateAssociation fails with \"is currently not accepted. Supported expressions are every half, 1, 2, 4, 8 or 12 hour(s), every specified day and time of the week, or a specific day in a specific week of the month\"", [s, why]),
	_pf_ssmas_fix, _pf_ssmas_url) if {
	some [name, why] in _pf_ssmas_bad
	s := _pf_ssmas_expr(name)
}

violation contains make_diag_full("pf-ssm-association-schedule", "ERROR", name,
	"Properties.ScheduleExpression",
	sprintf("'%s' has fewer than the 6 cron fields; CreateAssociation fails with \"is not a valid cron expression.\"", [s]),
	_pf_ssmas_fix, _pf_ssmas_url) if {
	some name in resources_of_type("AWS::SSM::Association")
	s := _pf_ssmas_expr(name)
	_pf_ssmas_kind(s) == "cron"
	not _pf_ssmas_fields(s)
}

violation contains make_diag_full("pf-ssm-association-schedule", "ERROR", name,
	"Properties.ApplyOnlyAtCronInterval",
	"ApplyOnlyAtCronInterval needs a cron() or at() schedule; CreateAssociation fails with \"ApplyOnlyAtCronInterval is not supported for Rate Schedule associations.\" / \"... for No Schedule associations.\"",
	_pf_ssmas_fix, _pf_ssmas_url) if {
	some name in resources_of_type("AWS::SSM::Association")
	_pf_ssmas_apply(name)
	not _pf_ssmas_cron_or_at(name)
}

_pf_ssmas_cron_or_at(name) if _pf_ssmas_kind(_pf_ssmas_expr(name)) in ["cron", "at"]

violation contains make_diag_full("pf-ssm-association-schedule", "ERROR", name,
	"Properties.ScheduleOffset",
	"ScheduleOffset needs ApplyOnlyAtCronInterval: true and a cron() that targets a weekday of the month (DAY#n or DAYL); CreateAssociation fails with \"ScheduleOffset is not supported for non ApplyOnlyAtCronInterval associations.\" / \"ScheduleOffset is valid with nth day of the week in the month cron expression only.\"",
	_pf_ssmas_fix, _pf_ssmas_url) if {
	some name in resources_of_type("AWS::SSM::Association")
	object.get(_pf_ssmas_props(name), "ScheduleOffset", "__pf_absent") != "__pf_absent"
	not _pf_ssmas_offset_ok(name)
}

_pf_ssmas_offset_ok(name) if {
	_pf_ssmas_apply(name)
	f := _pf_ssmas_six(_pf_ssmas_fields(_pf_ssmas_expr(name)))
	regex.match("[#L]", f[4])
}
