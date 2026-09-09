package cdk_preflight

import rego.v1

_pf_asgstbn_url := "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_PutScalingPolicy.html"

violation contains make_diag_full("pf-asg-step-both-bounds-null-forbidden", "ERROR", name,
	sprintf("Properties.StepAdjustments.%d", [i]),
	"the step sets neither MetricIntervalLowerBound nor MetricIntervalUpperBound; the policy create fails with \"Both lower and upper bounds of a StepAdjustment cannot be left unspecified\"",
	"Give the step a lower bound, an upper bound, or both", _pf_asgstbn_url) if {
	some name in resources_of_type("AWS::AutoScaling::ScalingPolicy")
	some i, s in _pf_aslib_steps(name)
	is_object(s)
	object.get(s, "MetricIntervalLowerBound", null) == null
	object.get(s, "MetricIntervalUpperBound", null) == null
}
