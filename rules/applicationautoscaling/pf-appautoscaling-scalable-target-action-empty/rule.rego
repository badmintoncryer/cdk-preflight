package cdk_preflight

import rego.v1

# An empty ScalableTargetAction passes CloudFormation's schema but PutScheduled
# Action answers "At least one of minimum capacity and maximum capacity should
# be provided". Either one alone is fine.
violation contains make_diag_full("pf-appautoscaling-scalable-target-action-empty", "ERROR", name,
	sprintf("Properties.ScheduledActions.%d.ScalableTargetAction", [item.index]),
	"ScalableTargetAction sets neither MinCapacity nor MaxCapacity; PutScheduledAction fails with \"At least one of minimum capacity and maximum capacity should be provided\"",
	"Set MinCapacity, MaxCapacity or both on the scheduled action",
	"https://docs.aws.amazon.com/autoscaling/application/APIReference/API_PutScheduledAction.html") if {
	some name in resources_of_type("AWS::ApplicationAutoScaling::ScalableTarget")
	some item in flatten_list(name, "Properties.ScheduledActions")
	sched := item.value
	is_object(sched)
	act := object.get(sched, "ScalableTargetAction", "__pf_absent")
	is_object(act)
	object.get(act, "MinCapacity", "__pf_absent") == "__pf_absent"
	object.get(act, "MaxCapacity", "__pf_absent") == "__pf_absent"
}
