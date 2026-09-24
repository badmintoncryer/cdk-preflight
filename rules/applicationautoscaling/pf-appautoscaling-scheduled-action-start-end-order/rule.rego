package cdk_preflight

import rego.v1

# "StartTime must be before EndTime". Both timestamps have to be written in the
# same shape before they can be ordered as strings, so the rule only fires when
# both are literal UTC instants; equal timestamps are left alone because the
# service was never measured on that case.
_pf_aasseo_ts(sched, k) := v if {
	v := object.get(sched, k, null)
	is_string(v)
	regex.match(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`, v)
}

violation contains make_diag_full("pf-appautoscaling-scheduled-action-start-end-order", "ERROR", name,
	sprintf("Properties.ScheduledActions.%d.StartTime", [item.index]),
	sprintf("StartTime '%s' is after EndTime '%s'; PutScheduledAction fails with \"StartTime must be before EndTime\"", [st, et]),
	"Swap the two timestamps so the window opens before it closes",
	"https://docs.aws.amazon.com/autoscaling/application/APIReference/API_PutScheduledAction.html") if {
	some name in resources_of_type("AWS::ApplicationAutoScaling::ScalableTarget")
	some item in flatten_list(name, "Properties.ScheduledActions")
	sched := item.value
	is_object(sched)
	st := _pf_aasseo_ts(sched, "StartTime")
	et := _pf_aasseo_ts(sched, "EndTime")
	st > et
}
