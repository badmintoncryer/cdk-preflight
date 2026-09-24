package cdk_preflight

import rego.v1

# An absent MetricIntervalUpperBound means plus infinity, so a second one would
# have to end where the first already does.
violation contains make_diag_full("pf-appautoscaling-step-adjustment-two-null-upper", "ERROR", name,
	"Properties.StepScalingPolicyConfiguration.StepAdjustments",
	"Two step adjustments leave MetricIntervalUpperBound out; PutScalingPolicy fails with \"At most one step adjustment may have an unspecified upper bound\"",
	"Keep one adjustment open at the top and give the others an explicit MetricIntervalUpperBound",
	"https://docs.aws.amazon.com/autoscaling/application/APIReference/API_StepAdjustment.html") if {
	some name in resources_of_type("AWS::ApplicationAutoScaling::ScalingPolicy")
	_pf_aaslib_step_two_open(name, "MetricIntervalUpperBound")
}
