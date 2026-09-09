package cdk_preflight

import rego.v1

# data.cdk_preflight.deploy_region is injected only in enforce mode with a
# concrete region; the rule skips otherwise.

violation contains make_diag_full("pf-cognito-sms-configuration-sns-region", "ERROR", name,
	"Properties.SmsConfiguration.SnsRegion",
	sprintf("SnsRegion is '%v' but the pool deploys to '%v'; the pool create fails with \"Invalid snsRegion. Allowed SNS region for %v is %v\"", [r, region, region, region]),
	"Set SmsConfiguration.SnsRegion to the pool's own region, or leave it out",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpool.html") if {
	some name in resources_of_type("AWS::Cognito::UserPool")
	region := data.cdk_preflight.deploy_region
	is_string(region)
	r := resolve(name, "Properties.SmsConfiguration.SnsRegion")
	is_string(r)
	r != region
}
