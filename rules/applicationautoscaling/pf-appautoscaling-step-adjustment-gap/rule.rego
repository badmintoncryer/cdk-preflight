package cdk_preflight

import rego.v1

# A gap is an upper bound that no adjustment continues from while another
# adjustment sits further up. Without that second half the check would fire on a
# perfectly good scale-in-only policy, whose single interval ends at 0 and is
# meant to.
violation contains make_diag_full("pf-appautoscaling-step-adjustment-gap", "ERROR", name,
	"Properties.StepScalingPolicyConfiguration.StepAdjustments",
	sprintf("No step adjustment starts at %v where step adjustment %d ends, and another one sits above it; PutScalingPolicy fails with \"Step adjustment intervals cannot have gaps between them\"", [top, i]),
	sprintf("Give the next adjustment MetricIntervalLowerBound %v, or close the range by widening this one", [top]),
	"https://docs.aws.amazon.com/autoscaling/application/APIReference/API_StepAdjustment.html") if {
	some name in resources_of_type("AWS::ApplicationAutoScaling::ScalingPolicy")
	not _pf_aaslib_step_two_open(name, "MetricIntervalLowerBound")
	not _pf_aaslib_step_two_open(name, "MetricIntervalUpperBound")
	adjs := _pf_aaslib_steps(name)
	some i, a in adjs
	top := _pf_aaslib_step_hi(a)
	not _pf_aaslib_step_any_covers(adjs, top)
	_pf_aaslib_step_any_above(adjs, top)
}
