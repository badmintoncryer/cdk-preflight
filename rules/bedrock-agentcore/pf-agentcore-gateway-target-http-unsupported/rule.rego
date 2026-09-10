package cdk_preflight

import rego.v1

# AWS::BedrockAgentCore::Gateway.ProtocolType is an enum with the single value
# MCP, and CreateGatewayTarget rejects an Http target on an MCP gateway, so
# TargetConfiguration.Http is unreachable through CloudFormation (measured
# 2026-09-10, both a cross-region and a same-region ARN fail identically).
# The schema offers the Http shape because the API supports gateway kinds
# CloudFormation cannot create. Same family as
# pf-agentcore-oauth2-provider-private-key-jwt.
_pf_achttp_props(name) := p if {
	p := input.resources[name].properties
	is_object(p)
}

violation contains make_diag_full("pf-agentcore-gateway-target-http-unsupported", "ERROR", name,
	"Properties.TargetConfiguration.Http",
	"Every gateway CloudFormation can create has ProtocolType MCP, and an MCP gateway rejects an Http target with \"HTTP target configuration is not supported for gateways with MCP protocol type\"",
	"Use an MCP target instead (Lambda, McpServer, OpenApiSchema or SmithyModel)",
	"https://docs.aws.amazon.com/bedrock-agentcore-control/latest/APIReference/API_CreateGatewayTarget.html") if {
	some name in resources_of_type("AWS::BedrockAgentCore::GatewayTarget")
	tc := object.get(_pf_achttp_props(name), "TargetConfiguration", {})
	is_object(tc)
	object.get(tc, "Http", null) != null
}
