package cdk_preflight

import rego.v1

# CreateGatewayTarget rejects an Http target on a gateway whose ProtocolType
# is MCP ("HTTP target configuration is not supported for gateways with MCP
# protocol type", measured 2026-09-10 with ProtocolType: MCP set). A gateway
# that leaves ProtocolType unset takes Http targets (gateway-target-http-
# runtime.html), so the rule fires only when the target's gateway is in the
# same template and sets ProtocolType MCP.
_pf_achttp_props(name) := p if {
	p := input.resources[name].properties
	is_object(p)
}

violation contains make_diag_full("pf-agentcore-gateway-target-http-unsupported", "ERROR", name,
	"Properties.TargetConfiguration.Http",
	sprintf("Gateway '%s' sets ProtocolType MCP, and an MCP gateway rejects an Http target with \"HTTP target configuration is not supported for gateways with MCP protocol type\"", [gw]),
	"Use an MCP target (Lambda, McpServer, OpenApiSchema or SmithyModel), or leave ProtocolType unset on the gateway that takes Http targets",
	"https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-target-http-runtime.html") if {
	some name in resources_of_type("AWS::BedrockAgentCore::GatewayTarget")
	tc := object.get(_pf_achttp_props(name), "TargetConfiguration", {})
	is_object(tc)
	object.get(tc, "Http", null) != null
	gw := _pf_bedrocklib_ref_target(resolve(name, "Properties.GatewayIdentifier"), "AWS::BedrockAgentCore::Gateway")
	resolve(gw, "Properties.ProtocolType") == "MCP"
}
