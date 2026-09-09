package cdk_preflight

import rego.v1

_pf_asgstov_url := "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_PutScalingPolicy.html"

violation contains make_diag_full("pf-asg-step-interval-overlap", "ERROR", name,
	"Properties.StepAdjustments",
	sprintf("steps %d and %d cover the same metric range; the policy create fails with \"StepAdjustment intervals cannot overlap\"", [i, j]),
	"Make the intervals touch at a single bound instead of overlapping", _pf_asgstov_url) if {
	some name in resources_of_type("AWS::AutoScaling::ScalingPolicy")
	_pf_aslib_step_wellformed(name)
	iv := _pf_aslib_step_ivals(name)
	some i, a in iv
	some j, b in iv
	i < j
	a[0] < b[1]
	b[0] < a[1]
}
