package cdk_preflight

import rego.v1

_pf_asglhaf_url := "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_PutLifecycleHook.html"

violation contains make_diag_full("pf-asg-lh-target-arn-format", "ERROR", name,
	"Properties.NotificationTargetARN",
	sprintf("NotificationTargetARN '%s' is not an ARN; the hook create fails with \"'NotificationTargetARN' must be a valid ARN\"", [v]),
	"Use the full ARN of the SNS topic, SQS queue or Lambda function", _pf_asglhaf_url) if {
	some name in resources_of_type("AWS::AutoScaling::LifecycleHook")
	v := resolve(name, "Properties.NotificationTargetARN")
	_pf_aslib_lit(v)
	not startswith(v, "arn:")
}
