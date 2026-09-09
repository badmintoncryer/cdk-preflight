package cdk_preflight

import rego.v1

_pf_asgiht_url := "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_CreateAutoScalingGroup.html"

violation contains make_diag_full("pf-asg-lifecyclehook-transition-enum", "ERROR", name,
	sprintf("Properties.LifecycleHookSpecificationList.%d.LifecycleTransition", [i]),
	sprintf("LifecycleTransition '%s' is not a lifecycle transition; the group create fails with \"'LifecycleTransition' must be one of: autoscaling:EC2_INSTANCE_LAUNCHING, autoscaling:EC2_INSTANCE_TERMINATING\"", [v]),
	"Use autoscaling:EC2_INSTANCE_LAUNCHING or autoscaling:EC2_INSTANCE_TERMINATING", _pf_asgiht_url) if {
	some name in resources_of_type("AWS::AutoScaling::AutoScalingGroup")
	some i, h in _pf_aslib_hooks(name)
	is_object(h)
	v := object.get(h, "LifecycleTransition", null)
	_pf_aslib_lit(v)
	not v in ["autoscaling:EC2_INSTANCE_LAUNCHING", "autoscaling:EC2_INSTANCE_TERMINATING"]
}
