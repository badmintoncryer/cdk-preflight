package cdk_preflight

import rego.v1

# Requests, Tokens and Connections are all optional on LimitEntry, but an
# entry with none of them fails with "Each entry must have at least one rate
# config: 'requests', 'tokens', or 'connections'".
violation contains make_diag_full("pf-agentcore-gateway-rate-limit-entry-metric", "ERROR", name,
	sprintf("Properties.Entries.%d", [i]),
	sprintf("Entry %d sets none of Requests, Tokens or Connections; CreateGatewayRateLimit fails with \"Each entry must have at least one rate config: 'requests', 'tokens', or 'connections'\"", [i]),
	"Add a Requests, Tokens or Connections rate to the entry, or remove the entry",
	"https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-rate-limits.html") if {
	some name in resources_of_type("AWS::BedrockAgentCore::GatewayRateLimit")
	entries := _pf_ll_raw(name, "Properties.Entries")
	_pf_countable_items(entries)
	some i, e in entries
	is_object(e)
	every k in ["Requests", "Tokens", "Connections"] {
		object.get(e, k, "__pf_absent") == "__pf_absent"
	}
}
