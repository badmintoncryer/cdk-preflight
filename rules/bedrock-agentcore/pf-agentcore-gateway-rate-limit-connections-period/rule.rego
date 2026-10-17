package cdk_preflight

import rego.v1

# Period is second | minute for every metric in the schema, but the
# description of Connections says per second only, and CreateGatewayRateLimit
# rejects minute ("Connection rate limits only support period 'second', got
# 'minute'").
violation contains make_diag_full("pf-agentcore-gateway-rate-limit-connections-period", "ERROR", name,
	sprintf("Properties.Entries.%d.Connections.%d.Period", [i, j]),
	sprintf("Entry %d limits Connections per '%s'; CreateGatewayRateLimit fails with \"Connection rate limits only support period 'second'\"", [i, c.Period]),
	"Use Period 'second' for Connections (Requests and Tokens also accept 'minute')",
	"https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-rate-limits.html") if {
	some name in resources_of_type("AWS::BedrockAgentCore::GatewayRateLimit")
	entries := _pf_ll_raw(name, "Properties.Entries")
	_pf_countable_items(entries)
	some i, e in entries
	is_object(e)
	conns := object.get(e, "Connections", [])
	is_array(conns)
	some j, c in conns
	is_object(c)
	is_string(c.Period)
	c.Period != "second"
}
