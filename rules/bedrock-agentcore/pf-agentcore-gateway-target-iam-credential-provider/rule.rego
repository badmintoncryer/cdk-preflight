package cdk_preflight

import rego.v1

# CredentialProvider is optional in the schema (GATEWAY_IAM_ROLE needs none for
# Lambda targets), but an OpenAPI or MCP server target signed with the gateway
# role must name the SigV4 service: "IamCredentialProvider is required for
# openApiSchema / mcpServer targets using IAM authentication".
_pf_gwtiam_kinds := ["OpenApiSchema", "McpServer"]

_pf_gwtiam_has_iam(c) if {
	cp := object.get(c, "CredentialProvider", null)
	is_object(cp)
	is_object(object.get(cp, "IamCredentialProvider", null))
}

violation contains make_diag_full("pf-agentcore-gateway-target-iam-credential-provider", "ERROR", name,
	sprintf("Properties.CredentialProviderConfigurations.%d.CredentialProvider", [c.index]),
	sprintf("%s target uses GATEWAY_IAM_ROLE without CredentialProvider.IamCredentialProvider; CreateGatewayTarget fails with \"IamCredentialProvider is required for %s targets using IAM authentication\"", [kind, kind]),
	"Add CredentialProvider.IamCredentialProvider with the Service to sign for (e.g. execute-api) and optionally its Region",
	"https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-building-adding-targets-authorization.html") if {
	some name in resources_of_type("AWS::BedrockAgentCore::GatewayTarget")
	some kind in _pf_gwtiam_kinds
	is_object(resolve(name, sprintf("Properties.TargetConfiguration.Mcp.%s", [kind])))
	some c in flatten_list(name, "Properties.CredentialProviderConfigurations")
	object.get(c.value, "CredentialProviderType", null) == "GATEWAY_IAM_ROLE"
	not _pf_gwtiam_has_iam(c.value)
}
