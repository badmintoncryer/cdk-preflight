package cdk_preflight

import rego.v1

# Actions holds at most two entries and they must be of different kinds: two
# ConfigurationBundle actions fail with "At most one configurationBundle
# action is allowed per rule" (measured 2026-09-10). The schema caps the list
# at two but does not constrain the mix.
_pf_acacts_props(name) := p if {
	p := input.resources[name].properties
	is_object(p)
}

violation contains make_diag_full("pf-agentcore-gateway-rule-single-bundle-action", "ERROR", name,
	"Properties.Actions",
	"The rule carries two ConfigurationBundle actions; CreateGatewayRule fails with \"At most one configurationBundle action is allowed per rule\"",
	"Keep one ConfigurationBundle action per rule (the second action, if any, must be a RouteToTarget)",
	"https://docs.aws.amazon.com/bedrock-agentcore-control/latest/APIReference/API_CreateGatewayRule.html") if {
	some name in resources_of_type("AWS::BedrockAgentCore::GatewayRule")
	acts := object.get(_pf_acacts_props(name), "Actions", [])
	bundles := [a | some a in acts; is_object(a); object.get(a, "ConfigurationBundle", null) != null]
	count(bundles) > 1
}
