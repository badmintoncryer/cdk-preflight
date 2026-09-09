package cdk_preflight

import rego.v1

_pf_asgihn_url := "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_CreateAutoScalingGroup.html"

violation contains make_diag_full("pf-asg-lifecyclehook-name-duplicate-rejected", "ERROR", name,
	sprintf("Properties.LifecycleHookSpecificationList.%d.LifecycleHookName", [j]),
	sprintf("two inline lifecycle hooks are both named '%s'; the group create fails with \"Multiple lifecycle hooks found for name '%s'\"", [v, v]),
	"Give every hook in the list its own LifecycleHookName", _pf_asgihn_url) if {
	some name in resources_of_type("AWS::AutoScaling::AutoScalingGroup")
	hooks := _pf_aslib_hooks(name)
	some i, a in hooks
	some j, b in hooks
	i < j
	is_object(a)
	is_object(b)
	v := object.get(a, "LifecycleHookName", null)
	_pf_aslib_lit(v)
	object.get(b, "LifecycleHookName", null) == v
}
