package cdk_preflight

import rego.v1

# MinAdjustmentMagnitude is the floor a percentage is rounded up to, so it is
# meaningless — and rejected — for the two absolute adjustment types. Matched
# against the two literals rather than "not PercentChangeInCapacity" so that an
# absent AdjustmentType stays pf-appautoscaling-step-adjustment-type-required's
# problem alone, and a Ref is left to the deploy.
violation contains make_diag_full("pf-appautoscaling-min-adjustment-magnitude-percent-only", "ERROR", name,
	"Properties.StepScalingPolicyConfiguration.MinAdjustmentMagnitude",
	sprintf("MinAdjustmentMagnitude is set but AdjustmentType is '%s'; PutScalingPolicy fails with \"Minimum adjustment magnitude is only allowed for adjustment type PercentChangeInCapacity\"", [at]),
	"Drop MinAdjustmentMagnitude, or switch AdjustmentType to PercentChangeInCapacity",
	"https://docs.aws.amazon.com/autoscaling/application/APIReference/API_StepScalingPolicyConfiguration.html") if {
	some name in resources_of_type("AWS::ApplicationAutoScaling::ScalingPolicy")
	cfg := object.get(_pf_aaslib_props(name), "StepScalingPolicyConfiguration", "__pf_absent")
	is_object(cfg)
	object.get(cfg, "MinAdjustmentMagnitude", "__pf_absent") != "__pf_absent"
	at := object.get(cfg, "AdjustmentType", "__pf_absent")
	at in {"ChangeInCapacity", "ExactCapacity"}
}
