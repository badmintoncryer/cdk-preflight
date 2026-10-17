package cdk_preflight

import rego.v1

# JWT_PASSTHROUGH is in the CredentialProviderType enum for every target,
# but the dev guide limits it to HTTP targets (passthrough and AgentCore
# Runtime), and CreateGatewayTarget rejects it on an McpServer target ("MCP
# server target does not support JWT_PASSTHROUGH credential provider type").
# Only McpServer is measured; Lambda is pf-agentcore-gateway-target-lambda-
# credential-type, and OpenApiSchema / SmithyModel are not checked.
violation contains make_diag_full("pf-agentcore-gateway-target-jwt-passthrough-http-only", "ERROR", name,
	sprintf("Properties.CredentialProviderConfigurations.%d.CredentialProviderType", [c.index]),
	"An McpServer target uses JWT_PASSTHROUGH; CreateGatewayTarget fails with \"MCP server target does not support JWT_PASSTHROUGH credential provider type\"",
	"Use OAUTH or API_KEY for the MCP server, or put the endpoint behind an Http passthrough target",
	"https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-building-adding-targets-authorization.html") if {
	some name in resources_of_type("AWS::BedrockAgentCore::GatewayTarget")
	is_object(resolve(name, "Properties.TargetConfiguration.Mcp.McpServer"))
	some c in flatten_list(name, "Properties.CredentialProviderConfigurations")
	object.get(c.value, "CredentialProviderType", null) == "JWT_PASSTHROUGH"
}
