package cdk_preflight

import rego.v1

# DimensionKeys is unique per gateway (schema description, dev guide); a
# second limit with the same keys fails with "A limit with dimensionKeys [...]
# already exists for this gateway" (ValidationException, not the documented
# 409). Keys are compared as written, order included; both limits must name
# the gateway the same way (same Ref / GetAtt target or the same literal).
violation contains make_diag_full("pf-agentcore-gateway-rate-limit-dimension-keys-unique", "ERROR", name,
	"Properties.DimensionKeys",
	sprintf("Rate limit '%s' on the same gateway already uses DimensionKeys %v; CreateGatewayRateLimit fails with \"A limit with dimensionKeys ... already exists for this gateway\"", [other, keys]),
	"Put all entries for one DimensionKeys combination into a single AWS::BedrockAgentCore::GatewayRateLimit",
	"https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-rate-limits.html") if {
	some name in resources_of_type("AWS::BedrockAgentCore::GatewayRateLimit")
	g := resolve(name, "Properties.GatewayIdentifier")
	keys := _pf_ll_raw(name, "Properties.DimensionKeys")
	_pf_countable_items(keys)
	some other in resources_of_type("AWS::BedrockAgentCore::GatewayRateLimit")
	other < name
	resolve(other, "Properties.GatewayIdentifier") == g
	_pf_ll_raw(other, "Properties.DimensionKeys") == keys
}
