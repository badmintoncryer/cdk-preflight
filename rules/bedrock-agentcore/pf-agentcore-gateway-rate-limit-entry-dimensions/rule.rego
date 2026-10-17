package cdk_preflight

import rego.v1

# Dimensions is a free-form map in the schema; CreateGatewayRateLimit needs
# one value per DimensionKeys entry ("dimensions map size (1) does not equal
# dimensionKeys length (2)"). Only the counts are compared, as the service does.
violation contains make_diag_full("pf-agentcore-gateway-rate-limit-entry-dimensions", "ERROR", name,
	sprintf("Properties.Entries.%d.Dimensions", [i]),
	sprintf("Entry %d has %d dimension values but DimensionKeys has %d keys; CreateGatewayRateLimit fails with \"dimensions map size (%d) does not equal dimensionKeys length (%d)\"", [i, count(d), count(keys), count(d), count(keys)]),
	"Give every entry one Dimensions value (or *) for each key in DimensionKeys",
	"https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-rate-limits.html") if {
	some name in resources_of_type("AWS::BedrockAgentCore::GatewayRateLimit")
	keys := _pf_ll_raw(name, "Properties.DimensionKeys")
	_pf_countable_items(keys)
	entries := _pf_ll_raw(name, "Properties.Entries")
	_pf_countable_items(entries)
	some i, e in entries
	d := object.get(e, "Dimensions", null)
	_pf_countable_entries(d)
	count(d) != count(keys)
}
