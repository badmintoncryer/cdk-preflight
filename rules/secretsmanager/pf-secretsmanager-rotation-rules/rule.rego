package cdk_preflight

import rego.v1

_pf_smrot_url := "https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotate-secrets_schedule.html"

_pf_smrot_fix := "Use ScheduleExpression rate(4 hours)..rate(23 hours) / rate(N days), or cron(0 H ... ? *) with hours at least four apart, and a Duration that fits inside the interval"

_pf_smrot_props(name) := props if {
	props := input.resources[name].properties
	is_object(props)
}

_pf_smrot_rules(name) := r if {
	r := object.get(_pf_smrot_props(name), "RotationRules", null)
	is_object(r)
}

_pf_smrot_expr(name) := e if {
	e := resolve(name, "Properties.RotationRules.ScheduleExpression")
	is_string(e)
}

_pf_smrot_days(name) := n if {
	v := resolve(name, "Properties.RotationRules.AutomaticallyAfterDays")
	n := _pf_smrot_num(v)
}

_pf_smrot_num(v) := v if is_number(v)

_pf_smrot_num(v) := to_number(v) if {
	is_string(v)
	regex.match("^[0-9]+$", v)
}

violation contains make_diag_full("pf-secretsmanager-rotation-rules", "ERROR", name,
	"Properties.RotationRules",
	"both AutomaticallyAfterDays and ScheduleExpression are set; RotateSecret fails with \"You cannot specify both rotation frequency and schedule expression together.\"",
	_pf_smrot_fix, _pf_smrot_url) if {
	some name in resources_of_type("AWS::SecretsManager::RotationSchedule")
	r := _pf_smrot_rules(name)
	object.get(r, "AutomaticallyAfterDays", "__pf_absent") != "__pf_absent"
	object.get(r, "ScheduleExpression", "__pf_absent") != "__pf_absent"
}

violation contains make_diag_full("pf-secretsmanager-rotation-rules", "ERROR", name,
	"Properties.RotationRules.AutomaticallyAfterDays",
	sprintf("AutomaticallyAfterDays %v is outside 1..1000; RotateSecret rejects it", [n]),
	_pf_smrot_fix, _pf_smrot_url) if {
	some name in resources_of_type("AWS::SecretsManager::RotationSchedule")
	n := _pf_smrot_days(name)
	_pf_smrot_outside(n, 1, 1000)
}

_pf_smrot_outside(n, lo, _) if n < lo

_pf_smrot_outside(n, _, hi) if n > hi

# rate(): [n, unit] or undefined when the expression is not a well-formed rate
_pf_smrot_rate(e) := [to_number(m[0][1]), m[0][2]] if {
	m := regex.find_all_string_submatch_n("^rate\\(([0-9]+) (hour|hours|day|days)\\)$", e, 1)
	count(m) == 1
}

violation contains make_diag_full("pf-secretsmanager-rotation-rules", "ERROR", name,
	"Properties.RotationRules.ScheduleExpression",
	sprintf("'%s' is neither rate(N hours|days) nor a 6-field cron(); RotateSecret fails with \"Invalid schedule expression.\" (minutes, weeks and 5-field cron are not accepted)", [e]),
	_pf_smrot_fix, _pf_smrot_url) if {
	some name in resources_of_type("AWS::SecretsManager::RotationSchedule")
	e := _pf_smrot_expr(name)
	not _pf_smrot_rate(e)
	not _pf_smrot_cron(e)
}

violation contains make_diag_full("pf-secretsmanager-rotation-rules", "ERROR", name,
	"Properties.RotationRules.ScheduleExpression",
	sprintf("'%s': an hourly rate must be between 4 and 23 hours; RotateSecret fails with \"Rate in hour should be least 4 and less than 24.\"", [e]),
	_pf_smrot_fix, _pf_smrot_url) if {
	some name in resources_of_type("AWS::SecretsManager::RotationSchedule")
	e := _pf_smrot_expr(name)
	[n, unit] := _pf_smrot_rate(e)
	startswith(unit, "hour")
	_pf_smrot_outside(n, 4, 23)
}

violation contains make_diag_full("pf-secretsmanager-rotation-rules", "ERROR", name,
	"Properties.RotationRules.ScheduleExpression",
	sprintf("'%s': a daily rate must be between 1 and 1000 days; RotateSecret fails with \"Rate in day should be greater than 0 and less than 1000.\"", [e]),
	_pf_smrot_fix, _pf_smrot_url) if {
	some name in resources_of_type("AWS::SecretsManager::RotationSchedule")
	e := _pf_smrot_expr(name)
	[n, unit] := _pf_smrot_rate(e)
	startswith(unit, "day")
	_pf_smrot_outside(n, 1, 1000)
}

# cron(): the six fields, or undefined when it is not a cron() with six fields
_pf_smrot_cron(e) := fields if {
	startswith(e, "cron(")
	endswith(e, ")")
	fields := split(substring(e, 5, count(e) - 6), " ")
	count(fields) == 6
}

# one [name, reason] per failed cron check (a function would have to return several reasons at once)
_pf_smrot_cron_fields(name) := _pf_smrot_cron(_pf_smrot_expr(name))

_pf_smrot_bad contains [name, "the minutes field must be 0 (rotation windows start on the hour)"] if {
	some name in resources_of_type("AWS::SecretsManager::RotationSchedule")
	_pf_smrot_cron_fields(name)[0] != "0"
}

_pf_smrot_bad contains [name, "the year field must be *"] if {
	some name in resources_of_type("AWS::SecretsManager::RotationSchedule")
	_pf_smrot_cron_fields(name)[5] != "*"
}

_pf_smrot_bad contains [name, "exactly one of day-of-month and day-of-week must be ?"] if {
	some name in resources_of_type("AWS::SecretsManager::RotationSchedule")
	f := _pf_smrot_cron_fields(name)
	f[2] == "?"
	f[4] == "?"
}

_pf_smrot_bad contains [name, "exactly one of day-of-month and day-of-week must be ?"] if {
	some name in resources_of_type("AWS::SecretsManager::RotationSchedule")
	f := _pf_smrot_cron_fields(name)
	f[2] != "?"
	f[4] != "?"
}

_pf_smrot_bad contains [name, "the hours field runs more often than every 4 hours (use a single hour, or 0/N with N >= 4)"] if {
	some name in resources_of_type("AWS::SecretsManager::RotationSchedule")
	_pf_smrot_hours_dense(_pf_smrot_cron_fields(name)[1])
}

_pf_smrot_hours_dense(h) if h == "*"

_pf_smrot_hours_dense(h) if contains(h, "-")

_pf_smrot_hours_dense(h) if {
	m := regex.find_all_string_submatch_n("^[0-9*]+/([0-9]+)$", h, 1)
	count(m) == 1
	to_number(m[0][1]) < 4
}

_pf_smrot_hours_dense(h) if {
	contains(h, ",")
	hours := [to_number(x) | some x in split(h, ","); regex.match("^[0-9]+$", x)]
	some i, a in hours
	some j, b in hours
	i != j
	a < b
	b - a < 4
}

violation contains make_diag_full("pf-secretsmanager-rotation-rules", "ERROR", name,
	"Properties.RotationRules.ScheduleExpression",
	sprintf("'%s': %s; RotateSecret fails with \"Invalid schedule expression.\"", [e, why]),
	_pf_smrot_fix, _pf_smrot_url) if {
	some [name, why] in _pf_smrot_bad
	e := _pf_smrot_expr(name)
}

# Duration
_pf_smrot_duration(name) := d if {
	d := resolve(name, "Properties.RotationRules.Duration")
	is_string(d)
}

_pf_smrot_dur_hours(d) := to_number(m[0][1]) if {
	m := regex.find_all_string_submatch_n("^([0-9]+)h$", d, 1)
	count(m) == 1
}

violation contains make_diag_full("pf-secretsmanager-rotation-rules", "ERROR", name,
	"Properties.RotationRules.Duration",
	sprintf("Duration '%s' must be a whole number of hours written as Nh (1h..24h); RotateSecret fails with \"Duration must be at least 1 hour, at most 24 hour.\"", [d]),
	_pf_smrot_fix, _pf_smrot_url) if {
	some name in resources_of_type("AWS::SecretsManager::RotationSchedule")
	d := _pf_smrot_duration(name)
	not _pf_smrot_dur_ok(d)
}

_pf_smrot_dur_ok(d) if {
	h := _pf_smrot_dur_hours(d)
	h >= 1
	h <= 24
}

violation contains make_diag_full("pf-secretsmanager-rotation-rules", "ERROR", name,
	"Properties.RotationRules.Duration",
	sprintf("Duration %s is longer than the rotation interval %s; RotateSecret fails with \"Duration cannot be greater than Rate in hour.\"", [d, e]),
	_pf_smrot_fix, _pf_smrot_url) if {
	some name in resources_of_type("AWS::SecretsManager::RotationSchedule")
	d := _pf_smrot_duration(name)
	h := _pf_smrot_dur_hours(d)
	e := _pf_smrot_expr(name)
	[n, unit] := _pf_smrot_rate(e)
	startswith(unit, "hour")
	h > n
}

violation contains make_diag_full("pf-secretsmanager-rotation-rules", "ERROR", name,
	"Properties.RotationRules.Duration",
	sprintf("the window starting at hour %s with Duration %s crosses midnight UTC; RotateSecret fails with \"Starting hour and duration must be within a day.\"", [f[1], d]),
	_pf_smrot_fix, _pf_smrot_url) if {
	some name in resources_of_type("AWS::SecretsManager::RotationSchedule")
	d := _pf_smrot_duration(name)
	h := _pf_smrot_dur_hours(d)
	f := _pf_smrot_cron(_pf_smrot_expr(name))
	regex.match("^[0-9]+$", f[1])
	to_number(f[1]) + h > 24
}
