package cdk_preflight

import rego.v1

# The credential provider union is validated per entry by the schema, but the
# target-type x credential-type compatibility table lives only in the dev
# guide; CreateGatewayTarget rejects a Lambda target with anything but
# GATEWAY_IAM_ROLE ("Lambda target only supports GATEWAY_IAM_ROLE credential
# provider type").
violation contains make_diag_full("pf-agentcore-gateway-target-lambda-credential-type", "ERROR", name,
	sprintf("Properties.CredentialProviderConfigurations.%d.CredentialProviderType", [c.index]),
	sprintf("Lambda targets accept only GATEWAY_IAM_ROLE but this target uses %s; CreateGatewayTarget fails with \"Lambda target only supports GATEWAY_IAM_ROLE credential provider type\"", [t]),
	"Use CredentialProviderType GATEWAY_IAM_ROLE, or switch to an OpenAPI / MCP server target for OAuth, API key, or JWT pass-through credentials",
	"https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-building-adding-targets-authorization.html") if {
	some name in resources_of_type("AWS::BedrockAgentCore::GatewayTarget")
	is_object(resolve(name, "Properties.TargetConfiguration.Mcp.Lambda"))
	some c in flatten_list(name, "Properties.CredentialProviderConfigurations")
	t := object.get(c.value, "CredentialProviderType", null)
	is_string(t)
	t != "GATEWAY_IAM_ROLE"
}
