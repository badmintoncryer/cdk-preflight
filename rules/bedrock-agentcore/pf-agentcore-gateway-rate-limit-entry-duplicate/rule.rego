package cdk_preflight

import rego.v1

# Nothing in the schema keeps two entries of one limit apart, but the same
# Dimensions twice fails with "Duplicate entry detected: dimensions
# {targetName=*} appears more than once in the same limit". Values are
# compared as written.
violation contains make_diag_full("pf-agentcore-gateway-rate-limit-entry-duplicate", "ERROR", name,
	sprintf("Properties.Entries.%d.Dimensions", [j]),
	sprintf("Entries %d and %d have the same Dimensions %v; CreateGatewayRateLimit fails with \"Duplicate entry detected: dimensions ... appears more than once in the same limit\"", [i, j, d]),
	"Merge the two entries, or give them different dimension values",
	"https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-rate-limits.html") if {
	some name in resources_of_type("AWS::BedrockAgentCore::GatewayRateLimit")
	entries := _pf_ll_raw(name, "Properties.Entries")
	_pf_countable_items(entries)
	some i, a in entries
	some j, b in entries
	i < j
	d := object.get(a, "Dimensions", null)
	_pf_countable_entries(d)
	object.get(b, "Dimensions", null) == d
}
