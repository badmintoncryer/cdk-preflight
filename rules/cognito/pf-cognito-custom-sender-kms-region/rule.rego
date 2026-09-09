package cdk_preflight

import rego.v1

# data.cdk_preflight.deploy_region is injected only in enforce mode with a
# concrete region; the rule skips otherwise.

violation contains make_diag_full("pf-cognito-custom-sender-kms-region", "ERROR", name,
	"Properties.LambdaConfig.KMSKeyID",
	sprintf("the custom sender KMS key is in '%v' but the pool deploys to '%v'; the CreateGrant call fails with \"Invalid arn %v\"", [r, region, r]),
	"Use a KMS key in the pool's own region",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpool.html") if {
	some name in resources_of_type("AWS::Cognito::UserPool")
	region := data.cdk_preflight.deploy_region
	is_string(region)
	r := _pf_coglib_arn_region(resolve(name, "Properties.LambdaConfig.KMSKeyID"))
	r != region
}
