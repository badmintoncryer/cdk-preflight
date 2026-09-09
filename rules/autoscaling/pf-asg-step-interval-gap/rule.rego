package cdk_preflight

import rego.v1

_pf_asgstgp_url := "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_PutScalingPolicy.html"

violation contains make_diag_full("pf-asg-step-interval-gap", "ERROR", name,
	"Properties.StepAdjustments",
	sprintf("the steps leave the metric range %v to %v uncovered; the policy create fails with \"StepAdjustment intervals cannot have gaps between them\"", [srt[k][1], srt[k + 1][0]]),
	"Close the gap: the upper bound of one step is the lower bound of the next", _pf_asgstgp_url) if {
	some name in resources_of_type("AWS::AutoScaling::ScalingPolicy")
	_pf_aslib_step_wellformed(name)
	srt := sort(_pf_aslib_step_ivals(name))
	some k in numbers.range(0, count(srt) - 2)
	srt[k][1] < srt[k + 1][0]
}
