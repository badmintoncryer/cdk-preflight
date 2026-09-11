package cdk_preflight

import rego.v1

# A weighted split routes a fraction of traffic each way, so the weights have
# to add up to 100: CreateGatewayRule fails with "Traffic split weights must
# sum to exactly 100, but sum is N" (measured 2026-09-10). The schema pins
# each weight to 1..99 and the list to exactly two entries but cannot express
# the sum.
_pf_acsplit_lists(name) := [[path, ts] |
	some i, act in object.get(_pf_acsplit_props(name), "Actions", [])
	some kind in ["WeightedOverride", "WeightedRoute"]
	block := object.get(object.get(act, "ConfigurationBundle", object.get(act, "RouteToTarget", {})), kind, null)
	is_object(block)
	ts := object.get(block, "TrafficSplit", null)
	is_array(ts)
	path := sprintf("Properties.Actions[%d].%s.TrafficSplit", [i, kind])
]

_pf_acsplit_props(name) := p if {
	p := input.resources[name].properties
	is_object(p)
}

violation contains make_diag_full("pf-agentcore-gateway-rule-traffic-split-sum", "ERROR", name,
	entry[0],
	sprintf("The traffic split weights add up to %v, not 100; CreateGatewayRule fails with \"Traffic split weights must sum to exactly 100, but sum is %v\"", [total, total]),
	"Make the weights add up to exactly 100 (for example 30 and 70)",
	"https://docs.aws.amazon.com/bedrock-agentcore-control/latest/APIReference/API_CreateGatewayRule.html") if {
	some name in resources_of_type("AWS::BedrockAgentCore::GatewayRule")
	some entry in _pf_acsplit_lists(name)
	weights := [w | some e in entry[1]; is_object(e); w := to_number(object.get(e, "Weight", null))]
	count(weights) == count(entry[1])
	total := sum(weights)
	total != 100
}
