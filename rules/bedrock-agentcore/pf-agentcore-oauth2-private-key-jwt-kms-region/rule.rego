package cdk_preflight

import rego.v1

# The KmsKeyArn pattern takes any region, but the dev guide says
# cross-Region keys are not supported, and CreateOauth2CredentialProvider
# fails with "KMS key region 'us-west-2' does not match credential provider
# region 'us-east-1'. Cross-region keys are not supported."
# data.cdk_preflight.deploy_region is defined only in enforce mode with a
# concrete region, otherwise this rule skips.
violation contains make_diag_full("pf-agentcore-oauth2-private-key-jwt-kms-region", "ERROR", name,
	"Properties.Oauth2ProviderConfigInput.CustomOauth2ProviderConfig.PrivateKeyJwtConfig.PrivateKeySource.KmsKeySource.KmsKeyArn",
	sprintf("The signing key lives in '%s' but the stack deploys to '%s'; CreateOauth2CredentialProvider fails with \"KMS key region '%s' does not match credential provider region '%s'. Cross-region keys are not supported.\"", [r, region, r, region]),
	"Use an asymmetric KMS key in the deploy region",
	"https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/private-key-jwt.html") if {
	some name in resources_of_type("AWS::BedrockAgentCore::OAuth2CredentialProvider")
	region := data.cdk_preflight.deploy_region
	is_string(region)
	arn := resolve(name, "Properties.Oauth2ProviderConfigInput.CustomOauth2ProviderConfig.PrivateKeyJwtConfig.PrivateKeySource.KmsKeySource.KmsKeyArn")
	is_string(arn)
	parts := split(arn, ":")
	count(parts) >= 6
	parts[2] == "kms"
	r := parts[3]
	r != ""
	r != region
}
