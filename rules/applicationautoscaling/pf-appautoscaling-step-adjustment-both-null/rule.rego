package cdk_preflight

import rego.v1

# Both bounds absent is the whole real line, which the service refuses even when
# it is the only adjustment in the policy.
violation contains make_diag_full("pf-appautoscaling-step-adjustment-both-null", "ERROR", name,
	sprintf("Properties.StepScalingPolicyConfiguration.StepAdjustments.%d", [i]),
	"This step adjustment sets neither MetricIntervalLowerBound nor MetricIntervalUpperBound; PutScalingPolicy fails with \"Both lower and upper bounds of a step adjustment cannot be left unspecified\"",
	"Set the bound that makes this a scale-out step (MetricIntervalLowerBound) or a scale-in step (MetricIntervalUpperBound)",
	"https://docs.aws.amazon.com/autoscaling/application/APIReference/API_StepAdjustment.html") if {
	some name in resources_of_type("AWS::ApplicationAutoScaling::ScalingPolicy")
	some i, a in _pf_aaslib_steps(name)
	object.get(a, "MetricIntervalLowerBound", "__pf_absent") == "__pf_absent"
	object.get(a, "MetricIntervalUpperBound", "__pf_absent") == "__pf_absent"
}
