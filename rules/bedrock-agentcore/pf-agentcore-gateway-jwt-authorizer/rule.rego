package cdk_preflight

import rego.v1

_pf_gwjwt_has_config(name) if is_object(resolve(name, "Properties.AuthorizerConfiguration"))

# PaymentManager shares the AuthorizerType / AuthorizerConfiguration pair and
# the same error ("AuthorizerConfiguration is required for CUSTOM_JWT
# authorizer type", measured 2026-09-05).
violation contains make_diag_full("pf-agentcore-gateway-jwt-authorizer", "ERROR", name,
	"Properties.AuthorizerConfiguration",
	"AuthorizerType is CUSTOM_JWT but AuthorizerConfiguration is missing; the create API requires it and the deployment fails with a ValidationException",
	"Add AuthorizerConfiguration.CustomJWTAuthorizer (discoveryUrl and allowedAudience/allowedClients), or switch AuthorizerType to AWS_IAM",
	"https://docs.aws.amazon.com/bedrock-agentcore-control/latest/APIReference/API_CreateGateway.html") if {
	some t in ["AWS::BedrockAgentCore::Gateway", "AWS::BedrockAgentCore::PaymentManager"]
	some name in resources_of_type(t)
	resolve(name, "Properties.AuthorizerType") == "CUSTOM_JWT"
	not _pf_gwjwt_has_config(name)
}
