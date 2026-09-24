package cdk_preflight

import rego.v1

# The same ordering RegisterScalableTarget enforces on the target itself is
# enforced again on every scheduled action: "Maximum capacity cannot be less
# than minimum capacity".
violation contains make_diag_full("pf-appautoscaling-scalable-target-action-min-max", "ERROR", name,
	sprintf("Properties.ScheduledActions.%d.ScalableTargetAction.MinCapacity", [item.index]),
	sprintf("ScalableTargetAction MinCapacity %v is above MaxCapacity %v; PutScheduledAction fails with \"Maximum capacity cannot be less than minimum capacity\"", [mn, mx]),
	"Lower MinCapacity to MaxCapacity or below (equal values are accepted)",
	"https://docs.aws.amazon.com/autoscaling/application/APIReference/API_PutScheduledAction.html") if {
	some name in resources_of_type("AWS::ApplicationAutoScaling::ScalableTarget")
	some item in flatten_list(name, "Properties.ScheduledActions")
	sched := item.value
	is_object(sched)
	act := object.get(sched, "ScalableTargetAction", "__pf_absent")
	is_object(act)
	mn := to_number(object.get(act, "MinCapacity", "__pf_absent"))
	mx := to_number(object.get(act, "MaxCapacity", "__pf_absent"))
	mn > mx
}
