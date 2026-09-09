package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cognito-pre-token-generation-config-tier", "ERROR", name,
	"Properties.LambdaConfig.PreTokenGenerationConfig.LambdaVersion",
	sprintf("PreTokenGenerationConfig.LambdaVersion %v needs a paid feature tier but UserPoolTier is LITE; the pool create fails with \"The following features need to be disabled for the LITE pricing tier configured: Token Customization with Pre-Token Generation Lambda %v\"", [v, v]),
	"Use UserPoolTier ESSENTIALS or PLUS, or set LambdaVersion to V1_0",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpool.html") if {
	some name in resources_of_type("AWS::Cognito::UserPool")
	resolve(name, "Properties.UserPoolTier") == "LITE"
	v := resolve(name, "Properties.LambdaConfig.PreTokenGenerationConfig.LambdaVersion")
	v in {"V2_0", "V3_0"}
}
