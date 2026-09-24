package cdk_preflight

import rego.v1

# rate() accepts minute(s) / hour(s) / day(s) only — seconds and weeks are
# rejected with the syntax message — and the value must be at least 1:
# rate(0 minutes) answers "Invalid schedule frequency. Run for ... are less than
# 60 seconds apart". Singular and plural are interchangeable.
_pf_aasrat_body(s) := b if {
	m := regex.find_all_string_submatch_n(`(?i)^rate\((.*)\)$`, s, 1)
	b := lower(trim_space(m[0][1]))
}

_pf_aasrat_parts(b) := m[0] if {
	m := regex.find_all_string_submatch_n(`^([0-9]+) *(minutes?|hours?|days?)$`, b, 1)
	count(m) == 1
}

violation contains make_diag_full("pf-appautoscaling-schedule-rate-unit", "ERROR", name,
	sprintf("Properties.ScheduledActions.%d.Schedule", [item.index]),
	sprintf("rate() takes a number and minute(s), hour(s) or day(s), but '%s' has '%s'; PutScheduledAction rejects it with \"Invalid schedule expression\"", [s, b]),
	"Write rate(<positive integer> <minute(s)|hour(s)|day(s)>)",
	"https://docs.aws.amazon.com/autoscaling/application/APIReference/API_PutScheduledAction.html") if {
	some name in resources_of_type("AWS::ApplicationAutoScaling::ScalableTarget")
	some item in flatten_list(name, "Properties.ScheduledActions")
	sched := item.value
	is_object(sched)
	s := object.get(sched, "Schedule", null)
	is_string(s)
	b := _pf_aasrat_body(s)
	not _pf_aasrat_parts(b)
}

violation contains make_diag_full("pf-appautoscaling-schedule-rate-unit", "ERROR", name,
	sprintf("Properties.ScheduledActions.%d.Schedule", [item.index]),
	sprintf("rate() needs a value of at least 1, but '%s' repeats every %v units; PutScheduledAction rejects it with \"Invalid schedule frequency\"", [s, v]),
	"Write rate(<positive integer> <minute(s)|hour(s)|day(s)>)",
	"https://docs.aws.amazon.com/autoscaling/application/APIReference/API_PutScheduledAction.html") if {
	some name in resources_of_type("AWS::ApplicationAutoScaling::ScalableTarget")
	some item in flatten_list(name, "Properties.ScheduledActions")
	sched := item.value
	is_object(sched)
	s := object.get(sched, "Schedule", null)
	is_string(s)
	v := to_number(_pf_aasrat_parts(_pf_aasrat_body(s))[1])
	v < 1
}
