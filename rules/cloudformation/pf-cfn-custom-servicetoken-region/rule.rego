package cdk_preflight

import rego.v1

# The ARN is a literal string in the template, and nothing on the synth side
# knows the deploy Region - this pack gets it from the validation context as
# data.cdk_preflight.deploy_region, which is only injected in enforce mode.
_pf_cfnsvctrgn_bad contains [name, arn, rgn] if {
	some name in _pf_cfn_custom_resources
	arn := resolve(name, "Properties.ServiceToken")
	is_string(arn)
	parts := split(arn, ":")
	count(parts) >= 6
	parts[0] == "arn"
	rgn := parts[3]
	rgn != ""
	rgn != data.cdk_preflight.deploy_region
}

violation contains make_diag_full("pf-cfn-custom-servicetoken-region", "ERROR", name,
	"Properties.ServiceToken",
	sprintf("ServiceToken %s is in %s but the stack deploys to %s; CloudFormation cannot reach it (\"Functions from '%s' are not reachable in this region\")", [arn, rgn, data.cdk_preflight.deploy_region, rgn]),
	"Point ServiceToken at an SNS topic or Lambda function in the stack's own Region",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudformation-customresource.html") if {
	some [name, arn, rgn] in _pf_cfnsvctrgn_bad
}
