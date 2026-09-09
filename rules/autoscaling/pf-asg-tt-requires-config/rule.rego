package cdk_preflight

import rego.v1

_pf_asgttrc_url := "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_PutScalingPolicy.html"

violation contains make_diag_full("pf-asg-tt-requires-config", "ERROR", name,
	"Properties.TargetTrackingConfiguration",
	"a TargetTrackingScaling policy has no TargetTrackingConfiguration; the policy create fails with \"You should provide a TargetTrackingConfiguration\"",
	"Add TargetTrackingConfiguration with a metric specification and a TargetValue", _pf_asgttrc_url) if {
	some name in resources_of_type("AWS::AutoScaling::ScalingPolicy")
	_pf_aslib_ptype(name) == "TargetTrackingScaling"
	_pf_aslib_absent(name, "TargetTrackingConfiguration")
}
