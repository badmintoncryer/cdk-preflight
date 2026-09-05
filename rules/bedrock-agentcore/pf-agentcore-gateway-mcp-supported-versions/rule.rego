package cdk_preflight

import rego.v1

# The schema types SupportedVersions as free strings; CreateGateway rejects
# anything outside the service's MCP protocol version list. Snapshot of that
# list as observed 2026-09-05 (the error message enumerates it) — extend when
# the service adds a version.
_pf_gwmcpver_supported := {"2025-03-26", "2025-06-18", "2025-11-25", "2026-07-28"}

violation contains make_diag_full("pf-agentcore-gateway-mcp-supported-versions", "ERROR", name,
	sprintf("Properties.ProtocolConfiguration.Mcp.SupportedVersions.%d", [v.index]),
	sprintf("MCP protocol version '%s' is not supported by AgentCore Gateway; CreateGateway fails with \"Unsupported MCP Version(s) are provided in request\"", [v.value]),
	sprintf("Use one of %s", [concat(", ", sort(_pf_gwmcpver_supported))]),
	"https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-using.html") if {
	some name in resources_of_type("AWS::BedrockAgentCore::Gateway")
	some v in flatten_list(name, "Properties.ProtocolConfiguration.Mcp.SupportedVersions")
	is_string(v.value)
	not v.value in _pf_gwmcpver_supported
}
