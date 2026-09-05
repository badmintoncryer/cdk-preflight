package cdk_preflight

import rego.v1

# The API needs privateKeyJwtConfig for this method, and the CloudFormation
# resource has no such property (the schema rejects it with F3002), so every
# template selecting PRIVATE_KEY_JWT fails at create time.
violation contains make_diag_full("pf-agentcore-oauth2-provider-private-key-jwt", "ERROR", name,
	"Properties.Oauth2ProviderConfigInput.CustomOauth2ProviderConfig.ClientAuthenticationMethod",
	"ClientAuthenticationMethod PRIVATE_KEY_JWT needs privateKeyJwtConfig, which the CloudFormation resource cannot express; CreateOauth2CredentialProvider fails with \"privateKeyJwtConfig is required when clientAuthenticationMethod is PRIVATE_KEY_JWT\"",
	"Use CLIENT_SECRET_BASIC or CLIENT_SECRET_POST, or create the provider outside CloudFormation",
	"https://docs.aws.amazon.com/bedrock-agentcore-control/latest/APIReference/API_CustomOauth2ProviderConfigInput.html") if {
	some name in resources_of_type("AWS::BedrockAgentCore::OAuth2CredentialProvider")
	resolve(name, "Properties.Oauth2ProviderConfigInput.CustomOauth2ProviderConfig.ClientAuthenticationMethod") == "PRIVATE_KEY_JWT"
}
