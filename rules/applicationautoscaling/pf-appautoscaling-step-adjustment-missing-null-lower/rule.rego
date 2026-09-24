package cdk_preflight

import rego.v1

# Bounds are offsets from the alarm threshold, so a negative lower bound is a
# scale-in step. The service insists the range below it be covered too, by an
# adjustment with no MetricIntervalLowerBound at all.
violation contains make_diag_full("pf-appautoscaling-step-adjustment-missing-null-lower", "ERROR", name,
	"Properties.StepScalingPolicyConfiguration.StepAdjustments",
	sprintf("Step adjustment %d has MetricIntervalLowerBound %v and no adjustment leaves MetricIntervalLowerBound out; PutScalingPolicy fails with \"There must be a step adjustment with an unspecified lower bound when one step adjustment has a negative lower bound\"", [i, bound]),
	"Drop MetricIntervalLowerBound from the lowest adjustment so it runs to minus infinity",
	"https://docs.aws.amazon.com/autoscaling/application/APIReference/API_StepAdjustment.html") if {
	some name in resources_of_type("AWS::ApplicationAutoScaling::ScalingPolicy")
	adjs := _pf_aaslib_steps(name)
	some i, a in adjs
	bound := _pf_aaslib_step_lo(a)
	bound < 0
	not _pf_aaslib_step_any_open(adjs, "MetricIntervalLowerBound")
}
