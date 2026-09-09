package cdk_preflight

import rego.v1

_pf_asgihd_url := "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_CreateAutoScalingGroup.html"

violation contains make_diag_full("pf-asg-lifecyclehook-defaultresult-enum", "ERROR", name,
	sprintf("Properties.LifecycleHookSpecificationList.%d.DefaultResult", [i]),
	sprintf("DefaultResult '%s' is not a hook result; the group create fails with \"'DefaultResult' must be one of: CONTINUE, ABANDON\"", [v]),
	"Use CONTINUE or ABANDON", _pf_asgihd_url) if {
	some name in resources_of_type("AWS::AutoScaling::AutoScalingGroup")
	some i, h in _pf_aslib_hooks(name)
	is_object(h)
	v := object.get(h, "DefaultResult", null)
	_pf_aslib_lit(v)
	not v in ["CONTINUE", "ABANDON"]
}
