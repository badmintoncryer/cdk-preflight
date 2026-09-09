package cdk_preflight

import rego.v1

_pf_asglht_url := "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_PutLifecycleHook.html"

_pf_asglht_ok(v) if v in ["autoscaling:EC2_INSTANCE_LAUNCHING", "autoscaling:EC2_INSTANCE_TERMINATING"]

violation contains make_diag_full("pf-asg-lh-transition-enum", "ERROR", name,
	"Properties.LifecycleTransition",
	sprintf("LifecycleTransition '%s' is not a lifecycle transition; the hook create fails with \"'LifecycleTransition' must be one of: autoscaling:EC2_INSTANCE_LAUNCHING, autoscaling:EC2_INSTANCE_TERMINATING\"", [v]),
	"Use autoscaling:EC2_INSTANCE_LAUNCHING or autoscaling:EC2_INSTANCE_TERMINATING",
	_pf_asglht_url) if {
	some name in resources_of_type("AWS::AutoScaling::LifecycleHook")
	v := resolve(name, "Properties.LifecycleTransition")
	_pf_aslib_lit(v)
	not _pf_asglht_ok(v)
}
