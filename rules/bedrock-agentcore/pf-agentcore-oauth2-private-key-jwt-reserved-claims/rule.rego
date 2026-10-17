package cdk_preflight

import rego.v1

# AdditionalHeaderClaims / AdditionalPayloadClaims are open maps in the
# schema. The dev guide reserves alg / typ in the header and iss / sub / jti /
# exp / iat / nbf in the payload; CreateOauth2CredentialProvider fails with
# "Claim key 'alg' is reserved and cannot be overridden in
# additionalHeaderClaims." (alg, typ and iss measured). The 10-claim cap is
# not checked: through CloudFormation, 11 claims fail in early validation with
# a message that does not name the property. Keys are compared as written.
_pf_acpkc_reserved := {
	"AdditionalHeaderClaims": {"alg", "typ"},
	"AdditionalPayloadClaims": {"iss", "sub", "jti", "exp", "iat", "nbf"},
}

_pf_acpkc_claims(name, kind) := m if {
	p := input.resources[name].properties
	is_object(p)
	m := p.Oauth2ProviderConfigInput.CustomOauth2ProviderConfig.PrivateKeyJwtConfig[kind]
	is_object(m)
}

violation contains make_diag_full("pf-agentcore-oauth2-private-key-jwt-reserved-claims", "ERROR", name,
	sprintf("Properties.Oauth2ProviderConfigInput.CustomOauth2ProviderConfig.PrivateKeyJwtConfig.%s.%s", [kind, k]),
	sprintf("Claim '%s' is reserved; CreateOauth2CredentialProvider fails with \"Claim key '%s' is reserved and cannot be overridden in %s\"", [k, k, kind]),
	"Remove the claim; AgentCore sets it itself",
	"https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/private-key-jwt.html") if {
	some name in resources_of_type("AWS::BedrockAgentCore::OAuth2CredentialProvider")
	some kind, reserved in _pf_acpkc_reserved
	some k, _ in _pf_acpkc_claims(name, kind)
	k in reserved
}

