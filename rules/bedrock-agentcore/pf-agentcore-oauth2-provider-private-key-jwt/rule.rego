package cdk_preflight

import rego.v1

# CreateOauth2CredentialProvider needs privateKeyJwtConfig when the method
# is PRIVATE_KEY_JWT ("privateKeyJwtConfig is required when
# clientAuthenticationMethod is PRIVATE_KEY_JWT", measured 2026-09-05). The
# schema has carried PrivateKeyJwtConfig since 2026-10 and nothing ties it to
# the method, so the rule fires only when the config is missing.
_pf_acpkj_cfg(name) := c if {
	p := input.resources[name].properties
	is_object(p)
	c := p.Oauth2ProviderConfigInput.CustomOauth2ProviderConfig
	is_object(c)
}

violation contains make_diag_full("pf-agentcore-oauth2-provider-private-key-jwt", "ERROR", name,
	"Properties.Oauth2ProviderConfigInput.CustomOauth2ProviderConfig.PrivateKeyJwtConfig",
	"ClientAuthenticationMethod is PRIVATE_KEY_JWT but PrivateKeyJwtConfig is missing; CreateOauth2CredentialProvider fails with \"privateKeyJwtConfig is required when clientAuthenticationMethod is PRIVATE_KEY_JWT\"",
	"Add PrivateKeyJwtConfig with PrivateKeySource.KmsKeySource.KmsKeyArn (an asymmetric SIGN_VERIFY key in the same region) and SigningAlgorithm, or use CLIENT_SECRET_BASIC / CLIENT_SECRET_POST",
	"https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/private-key-jwt.html") if {
	some name in resources_of_type("AWS::BedrockAgentCore::OAuth2CredentialProvider")
	resolve(name, "Properties.Oauth2ProviderConfigInput.CustomOauth2ProviderConfig.ClientAuthenticationMethod") == "PRIVATE_KEY_JWT"
	object.get(_pf_acpkj_cfg(name), "PrivateKeyJwtConfig", "__pf_absent") == "__pf_absent"
}
