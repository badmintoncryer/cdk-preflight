package cdk_preflight

import rego.v1

_pf_asgstrs_url := "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_PutScalingPolicy.html"

_pf_asgstrs_has(name) if count(_pf_aslib_steps(name)) > 0

violation contains make_diag_full("pf-asg-step-requires-stepadjustments", "ERROR", name,
	"Properties.StepAdjustments",
	"a StepScaling policy has no StepAdjustments; the policy create fails with \"You should specify at least one StepAdjustment with a StepScaling policy\"",
	"Add at least one StepAdjustment", _pf_asgstrs_url) if {
	some name in resources_of_type("AWS::AutoScaling::ScalingPolicy")
	_pf_aslib_ptype(name) == "StepScaling"
	not _pf_asgstrs_has(name)
}
