package cdk_preflight

import rego.v1

# The schema rejects an *empty* AllowedAudience / AllowedClients array (F3018)
# but not a CustomJWTAuthorizer that omits all four claim filters; the control
# plane then fails with "At least one of allowedAudience or allowedClients or
# allowedScopes or CustomClaims must be defined for CUSTOM_JWT authorizer"
# (Gateway wording; Runtime and Harness say "must be present with at least
# one item"). PaymentManager shares the shape but is not measured.
_pf_jwtclaims_types := ["AWS::BedrockAgentCore::Gateway", "AWS::BedrockAgentCore::Runtime", "AWS::BedrockAgentCore::Harness"]

_pf_jwtclaims_has_filter(jwt) if {
	some key in ["AllowedAudience", "AllowedClients", "AllowedScopes", "CustomClaims"]
	object.get(jwt, key, "__pf_absent") != "__pf_absent"
}

violation contains make_diag_full("pf-agentcore-jwt-authorizer-claims", "ERROR", name,
	"Properties.AuthorizerConfiguration.CustomJWTAuthorizer",
	"CustomJWTAuthorizer sets none of AllowedAudience, AllowedClients, AllowedScopes, or CustomClaims; the deployment fails with \"At least one of allowedAudience or allowedClients or allowedScopes or CustomClaims must be defined for CUSTOM_JWT authorizer\"",
	"Add at least one claim filter, e.g. AllowedClients with the OAuth client IDs that may call this resource",
	"https://docs.aws.amazon.com/bedrock-agentcore-control/latest/APIReference/API_CustomJWTAuthorizerConfiguration.html") if {
	some t in _pf_jwtclaims_types
	some name in resources_of_type(t)
	props := input.resources[name].properties
	is_object(props)
	auth := object.get(props, "AuthorizerConfiguration", null)
	is_object(auth)
	jwt := object.get(auth, "CustomJWTAuthorizer", null)
	is_object(jwt)
	not _pf_jwtclaims_has_filter(jwt)
}
