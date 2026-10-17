package cdk_preflight

import rego.v1

# TrafficSplit names only have a pattern in the schema; the dev guide says
# they must be unique, and CreateGatewayRule fails with "Duplicate
# trafficSplit entry name: a" (WeightedRoute) / "Duplicate traffic split entry
# name: a" (WeightedOverride). Names are compared as written.
_pf_actsnu_lists(name) := [[i, kind, ts] |
	p := input.resources[name].properties
	is_object(p)
	acts := object.get(p, "Actions", [])
	is_array(acts)
	some i, act in acts
	is_object(act)
	some kind in ["WeightedOverride", "WeightedRoute"]
	block := object.get(object.get(act, "ConfigurationBundle", object.get(act, "RouteToTarget", {})), kind, null)
	is_object(block)
	ts := object.get(block, "TrafficSplit", null)
	_pf_countable_items(ts)
]

violation contains make_diag_full("pf-agentcore-gateway-rule-traffic-split-name-unique", "ERROR", name,
	sprintf("Properties.Actions.%d.%s.TrafficSplit.%d.Name", [l[0], l[1], k]),
	sprintf("Traffic split name '%s' appears twice; CreateGatewayRule fails with \"Duplicate trafficSplit entry name: %s\"", [n, n]),
	"Give each traffic split entry its own Name",
	"https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-rules.html") if {
	some name in resources_of_type("AWS::BedrockAgentCore::GatewayRule")
	some l in _pf_actsnu_lists(name)
	some j, a in l[2]
	some k, b in l[2]
	j < k
	n := object.get(a, "Name", null)
	is_string(n)
	object.get(b, "Name", null) == n
}
