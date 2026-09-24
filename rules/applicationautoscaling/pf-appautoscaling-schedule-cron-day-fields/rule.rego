package cdk_preflight

import rego.v1

# Measured against PutScheduledAction: (?,*) (*,?) (1,?) (?,2) are accepted and
# (*,*) (1,2) (?,?) are rejected — exactly one of the two day fields has to be
# '?'. The field count is NOT fixed (5, 6 and 7 fields all deploy), so the two
# day fields are read positionally from a 5-or-more field expression.
_pf_aascdf_fields(s) := f if {
	m := regex.find_all_string_submatch_n(`(?i)^cron\((.*)\)$`, s, 1)
	f := regex.split(`\s+`, trim_space(m[0][1]))
	count(f) >= 5
}

violation contains make_diag_full("pf-appautoscaling-schedule-cron-day-fields", "ERROR", name,
	sprintf("Properties.ScheduledActions.%d.Schedule", [item.index]),
	sprintf("cron() day-of-month is '%s' and day-of-week is '%s' in '%s'; PutScheduledAction needs '?' in exactly one of the two and rejects this with \"Invalid CRON expression\"", [f[2], f[4], s]),
	"Put '?' in whichever of day-of-month / day-of-week you are not specifying",
	"https://docs.aws.amazon.com/autoscaling/application/userguide/scheduled-scaling-using-cron-expressions.html") if {
	some name in resources_of_type("AWS::ApplicationAutoScaling::ScalableTarget")
	some item in flatten_list(name, "Properties.ScheduledActions")
	sched := item.value
	is_object(sched)
	s := object.get(sched, "Schedule", null)
	is_string(s)
	f := _pf_aascdf_fields(s)
	count({i | some i in [2, 4]; f[i] == "?"}) != 1
}
