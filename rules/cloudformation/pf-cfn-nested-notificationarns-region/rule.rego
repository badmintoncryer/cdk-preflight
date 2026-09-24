package cdk_preflight

import rego.v1

# Same shape as the custom-resource ServiceToken: a literal ARN whose Region no
# synth-side layer can compare against, because the deploy Region only reaches
# the rule through data.cdk_preflight.deploy_region in enforce mode.
_pf_cfnnarn_bad contains [name, idx, arn, rgn] if {
	some name in resources_of_type("AWS::CloudFormation::Stack")
	some a in flatten_list(name, "Properties.NotificationARNs")
	is_string(a.value)
	parts := split(a.value, ":")
	count(parts) >= 6
	parts[0] == "arn"
	rgn := parts[3]
	rgn != data.cdk_preflight.deploy_region
	idx := a.index
	arn := a.value
}

violation contains make_diag_full("pf-cfn-nested-notificationarns-region", "ERROR", name,
	sprintf("Properties.NotificationARNs.%d", [idx]),
	sprintf("Notification topic %s is in %s but the stack deploys to %s; CloudFormation fails the nested stack with \"Invalid parameter: TopicArn\"", [arn, rgn, data.cdk_preflight.deploy_region]),
	"Use an SNS topic in the same Region as the stack",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudformation-stack.html") if {
	some [name, idx, arn, rgn] in _pf_cfnnarn_bad
}
