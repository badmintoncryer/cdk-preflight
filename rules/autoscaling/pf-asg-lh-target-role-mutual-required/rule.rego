package cdk_preflight

import rego.v1

_pf_asglhtr_url := "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_PutLifecycleHook.html"

violation contains make_diag_full("pf-asg-lh-target-role-mutual-required", "ERROR", name,
	"Properties.NotificationTargetARN",
	"RoleARN is set but NotificationTargetARN is not; the hook create fails with \"'NotificationTargetARN' parameter required when 'RoleARN' parameter is specified\"",
	"Set NotificationTargetARN to the SNS topic or SQS queue, or drop RoleARN", _pf_asglhtr_url) if {
	some name in resources_of_type("AWS::AutoScaling::LifecycleHook")
	not _pf_aslib_absent(name, "RoleARN")
	_pf_aslib_absent(name, "NotificationTargetARN")
}

violation contains make_diag_full("pf-asg-lh-target-role-mutual-required", "ERROR", name,
	"Properties.RoleARN",
	"NotificationTargetARN is set but RoleARN is not; the hook create fails with \"'RoleARN' parameter required when 'NotificationTargetARN' parameter is specified\"",
	"Set RoleARN to a role Auto Scaling can assume to publish to the target", _pf_asglhtr_url) if {
	some name in resources_of_type("AWS::AutoScaling::LifecycleHook")
	not _pf_aslib_absent(name, "NotificationTargetARN")
	_pf_aslib_absent(name, "RoleARN")
	not _pf_aslib_target_lambda(name)
}
