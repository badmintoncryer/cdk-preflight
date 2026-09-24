package cdk_preflight

import rego.v1

# The mirror image: a positive upper bound is a scale-out step, and the range
# above it has to be covered by an adjustment with no MetricIntervalUpperBound.
violation contains make_diag_full("pf-appautoscaling-step-adjustment-missing-null-upper", "ERROR", name,
	"Properties.StepScalingPolicyConfiguration.StepAdjustments",
	sprintf("Step adjustment %d has MetricIntervalUpperBound %v and no adjustment leaves MetricIntervalUpperBound out; PutScalingPolicy fails with \"There must be a step adjustment with an unspecified upper bound when one step adjustment has a positive upper bound\"", [i, bound]),
	"Drop MetricIntervalUpperBound from the highest adjustment so it runs to plus infinity",
	"https://docs.aws.amazon.com/autoscaling/application/APIReference/API_StepAdjustment.html") if {
	some name in resources_of_type("AWS::ApplicationAutoScaling::ScalingPolicy")
	adjs := _pf_aaslib_steps(name)
	some i, a in adjs
	bound := _pf_aaslib_step_hi(a)
	bound > 0
	not _pf_aaslib_step_any_open(adjs, "MetricIntervalUpperBound")
}
