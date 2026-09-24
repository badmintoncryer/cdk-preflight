package cdk_preflight

import rego.v1

# AdjustmentType has no default: without it the service cannot tell whether a
# ScalingAdjustment is a delta, a percentage or a capacity.
violation contains make_diag_full("pf-appautoscaling-step-adjustment-type-required", "ERROR", name,
	"Properties.StepScalingPolicyConfiguration.AdjustmentType",
	"StepScalingPolicyConfiguration has no AdjustmentType; PutScalingPolicy fails with \"Adjustment type must be specified\"",
	"Set AdjustmentType to ChangeInCapacity, PercentChangeInCapacity or ExactCapacity",
	"https://docs.aws.amazon.com/autoscaling/application/APIReference/API_StepScalingPolicyConfiguration.html") if {
	some name in resources_of_type("AWS::ApplicationAutoScaling::ScalingPolicy")
	cfg := object.get(_pf_aaslib_props(name), "StepScalingPolicyConfiguration", "__pf_absent")
	is_object(cfg)
	object.get(cfg, "AdjustmentType", "__pf_absent") == "__pf_absent"
}
