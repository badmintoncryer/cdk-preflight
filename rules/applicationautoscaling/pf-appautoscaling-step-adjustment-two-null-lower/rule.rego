package cdk_preflight

import rego.v1

# An absent MetricIntervalLowerBound means minus infinity, so a second one would
# have to start where the first already does.
violation contains make_diag_full("pf-appautoscaling-step-adjustment-two-null-lower", "ERROR", name,
	"Properties.StepScalingPolicyConfiguration.StepAdjustments",
	"Two step adjustments leave MetricIntervalLowerBound out; PutScalingPolicy fails with \"At most one step adjustment may have an unspecified lower bound\"",
	"Keep one adjustment open at the bottom and give the others an explicit MetricIntervalLowerBound",
	"https://docs.aws.amazon.com/autoscaling/application/APIReference/API_StepAdjustment.html") if {
	some name in resources_of_type("AWS::ApplicationAutoScaling::ScalingPolicy")
	_pf_aaslib_step_two_open(name, "MetricIntervalLowerBound")
}
