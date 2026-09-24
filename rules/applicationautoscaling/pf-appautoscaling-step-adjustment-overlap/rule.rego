package cdk_preflight

import rego.v1

# Interval algebra only makes sense once each side has at most one infinite end
# — two adjustments that both run to minus infinity always intersect, and the
# service answers that with the "at most one ... unspecified lower bound"
# sentence, which pf-appautoscaling-step-adjustment-two-null-lower carries.
violation contains make_diag_full("pf-appautoscaling-step-adjustment-overlap", "ERROR", name,
	"Properties.StepScalingPolicyConfiguration.StepAdjustments",
	sprintf("Step adjustments %d and %d cover overlapping metric intervals; PutScalingPolicy fails with \"Step adjustment intervals cannot overlap\"", [i, j]),
	"Let the intervals meet end to end: one adjustment's MetricIntervalUpperBound is the next one's MetricIntervalLowerBound",
	"https://docs.aws.amazon.com/autoscaling/application/APIReference/API_StepAdjustment.html") if {
	some name in resources_of_type("AWS::ApplicationAutoScaling::ScalingPolicy")
	not _pf_aaslib_step_two_open(name, "MetricIntervalLowerBound")
	not _pf_aaslib_step_two_open(name, "MetricIntervalUpperBound")
	adjs := _pf_aaslib_steps(name)
	some i, a in adjs
	some j, b in adjs
	i < j
	not _pf_aaslib_step_disjoint(a, b)
	not _pf_aaslib_step_disjoint(b, a)
}
