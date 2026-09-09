package cdk_preflight

import rego.v1

_pf_asgssa_url := "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_PutScalingPolicy.html"

violation contains make_diag_full("pf-asg-simple-requires-scalingadjustment", "ERROR", name,
	"Properties.ScalingAdjustment",
	"a SimpleScaling policy has no ScalingAdjustment (PolicyType defaults to SimpleScaling when it is left out); the policy create fails with \"Scaling increment must be specified for a SimpleScaling policy\"",
	"Set ScalingAdjustment, or pick a different PolicyType", _pf_asgssa_url) if {
	some name in resources_of_type("AWS::AutoScaling::ScalingPolicy")
	_pf_aslib_ptype(name) == "SimpleScaling"
	_pf_aslib_absent(name, "ScalingAdjustment")
}
