package cdk_preflight

import rego.v1

_pf_gwjwt_has_config(name) if is_object(resolve(name, "Properties.AuthorizerConfiguration"))

violation contains make_diag_full("pf-agentcore-gateway-jwt-authorizer", "ERROR", name,
	"Properties.AuthorizerConfiguration",
	"AuthorizerType is CUSTOM_JWT but AuthorizerConfiguration is missing; the CreateGateway API requires it and the deployment fails with a ValidationException",
	"Add AuthorizerConfiguration.CustomJWTAuthorizer (discoveryUrl and allowedAudience/allowedClients), or switch AuthorizerType to AWS_IAM",
	"https://docs.aws.amazon.com/bedrock-agentcore-control/latest/APIReference/API_CreateGateway.html") if {
	some name in resources_of_type("AWS::BedrockAgentCore::Gateway")
	resolve(name, "Properties.AuthorizerType") == "CUSTOM_JWT"
	not _pf_gwjwt_has_config(name)
}
