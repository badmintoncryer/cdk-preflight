package cdk_preflight

import rego.v1

# The registry schema knows StepAdjustments but requires neither its presence
# nor a minimum length, so an absent key and an empty array both reach the
# service, which answers both with the same sentence.
violation contains make_diag_full("pf-appautoscaling-step-adjustments-required", "ERROR", name,
	"Properties.StepScalingPolicyConfiguration.StepAdjustments",
	"StepScalingPolicyConfiguration carries no step adjustment; PutScalingPolicy fails with \"There must be at least one step adjustment\"",
	"Add a step adjustment, for example MetricIntervalLowerBound 0 with ScalingAdjustment 1",
	"https://docs.aws.amazon.com/autoscaling/application/APIReference/API_StepScalingPolicyConfiguration.html") if {
	some name in resources_of_type("AWS::ApplicationAutoScaling::ScalingPolicy")
	count(_pf_aaslib_steps(name)) == 0
}
