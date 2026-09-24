package cdk_preflight

import rego.v1

# CloudFormation documents ScalableTargetAction as "Required: No" and its schema
# agrees, but PutScheduledAction refuses the call with "ScalableTargetAction
# must be set": a scheduled action with no capacity to apply does nothing.
violation contains make_diag_full("pf-appautoscaling-scalable-target-action-required", "ERROR", name,
	sprintf("Properties.ScheduledActions.%d", [item.index]),
	sprintf("Scheduled action '%s' has no ScalableTargetAction; PutScheduledAction fails with \"ScalableTargetAction must be set\"", [n]),
	"Add ScalableTargetAction with MinCapacity, MaxCapacity or both",
	"https://docs.aws.amazon.com/autoscaling/application/APIReference/API_PutScheduledAction.html") if {
	some name in resources_of_type("AWS::ApplicationAutoScaling::ScalableTarget")
	some item in flatten_list(name, "Properties.ScheduledActions")
	sched := item.value
	is_object(sched)
	n := object.get(sched, "ScheduledActionName", null)
	is_string(n)
	object.get(sched, "ScalableTargetAction", "__pf_absent") == "__pf_absent"
}
