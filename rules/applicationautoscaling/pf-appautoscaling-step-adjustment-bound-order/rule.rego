package cdk_preflight

import rego.v1

# Equal bounds describe an empty interval, and the service rejects them with the
# same sentence it uses for inverted ones.
violation contains make_diag_full("pf-appautoscaling-step-adjustment-bound-order", "ERROR", name,
	sprintf("Properties.StepScalingPolicyConfiguration.StepAdjustments.%d.MetricIntervalUpperBound", [i]),
	sprintf("MetricIntervalUpperBound %v is not above MetricIntervalLowerBound %v; PutScalingPolicy fails with \"Lower bound must be less than upper bound for a step adjustment\"", [top, bottom]),
	"Raise MetricIntervalUpperBound above MetricIntervalLowerBound; equal bounds are rejected too",
	"https://docs.aws.amazon.com/autoscaling/application/APIReference/API_StepAdjustment.html") if {
	some name in resources_of_type("AWS::ApplicationAutoScaling::ScalingPolicy")
	some i, a in _pf_aaslib_steps(name)
	bottom := _pf_aaslib_step_lo(a)
	top := _pf_aaslib_step_hi(a)
	top <= bottom
}
