package cdk_preflight

import rego.v1

# at(2035-01-01T00:00:00Z) is rejected with "Invalid format: ... is malformed at
# \"Z\"" and at(2035-01-01) with "... is too short": the offset belongs in
# Timezone, not in the expression. Seconds are optional on purpose — only a form
# that is certainly rejected fires.
_pf_aasatf_body(s) := b if {
	m := regex.find_all_string_submatch_n(`(?i)^at\((.*)\)$`, s, 1)
	b := m[0][1]
}

violation contains make_diag_full("pf-appautoscaling-schedule-at-format", "ERROR", name,
	sprintf("Properties.ScheduledActions.%d.Schedule", [item.index]),
	sprintf("at() takes yyyy-mm-ddThh:mm:ss and no timezone suffix, but '%s' has '%s'; PutScheduledAction rejects it with \"Invalid schedule at DateTime expression\"", [s, b]),
	"Write at(2035-01-01T00:00:00) and put the offset in the scheduled action's Timezone",
	"https://docs.aws.amazon.com/autoscaling/application/APIReference/API_PutScheduledAction.html") if {
	some name in resources_of_type("AWS::ApplicationAutoScaling::ScalableTarget")
	some item in flatten_list(name, "Properties.ScheduledActions")
	sched := item.value
	is_object(sched)
	s := object.get(sched, "Schedule", null)
	is_string(s)
	b := _pf_aasatf_body(s)
	not regex.match(`^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9](:[0-5][0-9])?$`, b)
}
