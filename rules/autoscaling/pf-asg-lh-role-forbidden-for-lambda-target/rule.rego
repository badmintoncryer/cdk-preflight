package cdk_preflight

import rego.v1

_pf_asglhrl_url := "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_PutLifecycleHook.html"

violation contains make_diag_full("pf-asg-lh-role-forbidden-for-lambda-target", "ERROR", name,
	"Properties.RoleARN",
	"NotificationTargetARN is a Lambda function, so RoleARN must be left out; the hook create fails with \"'RoleARN' parameter should not be specified when 'NotificationTargetARN' is a Lambda function\"",
	"Drop RoleARN; Auto Scaling invokes the function through its own resource policy", _pf_asglhrl_url) if {
	some name in resources_of_type("AWS::AutoScaling::LifecycleHook")
	_pf_aslib_target_lambda(name)
	not _pf_aslib_absent(name, "RoleARN")
}
