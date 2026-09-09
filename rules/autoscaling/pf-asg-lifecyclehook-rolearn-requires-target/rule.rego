package cdk_preflight

import rego.v1

_pf_asgihr_url := "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_CreateAutoScalingGroup.html"

violation contains make_diag_full("pf-asg-lifecyclehook-rolearn-requires-target", "ERROR", name,
	sprintf("Properties.LifecycleHookSpecificationList.%d.NotificationTargetARN", [i]),
	"the inline lifecycle hook sets RoleARN but no NotificationTargetARN; the group create fails with \"'NotificationTargetARN' parameter required when 'RoleARN' parameter is specified\"",
	"Add NotificationTargetARN, or drop RoleARN", _pf_asgihr_url) if {
	some name in resources_of_type("AWS::AutoScaling::AutoScalingGroup")
	some i, h in _pf_aslib_hooks(name)
	is_object(h)
	object.get(h, "RoleARN", "__pf_absent") != "__pf_absent"
	object.get(h, "NotificationTargetARN", "__pf_absent") == "__pf_absent"
}
