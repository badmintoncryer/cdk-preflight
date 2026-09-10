package cdk_preflight

import rego.v1

# Priority orders the rules on a gateway and must be unique per gateway:
# CreateGatewayRule rejects a collision with "Priority N conflicts with an
# existing rule" (measured 2026-09-10). The schema only carries the range.
violation contains make_diag_full("pf-agentcore-gateway-rule-priority-unique", "ERROR", name,
	"Properties.Priority",
	sprintf("Priority %v is already taken by resource '%s' on the same gateway; CreateGatewayRule fails with \"Priority %v conflicts with an existing rule\"", [prio, other, prio]),
	"Give each rule on a gateway its own priority",
	"https://docs.aws.amazon.com/bedrock-agentcore-control/latest/APIReference/API_CreateGatewayRule.html") if {
	some name in resources_of_type("AWS::BedrockAgentCore::GatewayRule")
	prio := resolve(name, "Properties.Priority")
	gw := resolve(name, "Properties.GatewayIdentifier")
	some other in resources_of_type("AWS::BedrockAgentCore::GatewayRule")
	other < name
	resolve(other, "Properties.Priority") == prio
	resolve(other, "Properties.GatewayIdentifier") == gw
}
