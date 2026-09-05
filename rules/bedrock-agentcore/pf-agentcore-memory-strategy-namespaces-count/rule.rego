package cdk_preflight

import rego.v1

# The API documents Namespaces as "Fixed number of 1 item" but the CloudFormation
# schema carries no maxItems (an empty list is caught, F3032). Two namespaces
# fail at CreateMemory with "Member must have length less than or equal to 1".
violation contains make_diag_full("pf-agentcore-memory-strategy-namespaces-count", "ERROR", name,
	sprintf("Properties.MemoryStrategies.%d.%s.Namespaces", [s.index, kind]),
	sprintf("Strategy '%s' lists %d namespaces but a strategy accepts exactly one; CreateMemory fails with \"Member must have length less than or equal to 1\"", [object.get(strat, "Name", "<unnamed>"), count(ns)]),
	"Keep one namespace per strategy; add another strategy for a second namespace",
	"https://docs.aws.amazon.com/bedrock-agentcore-control/latest/APIReference/API_SemanticMemoryStrategyInput.html") if {
	some name in resources_of_type("AWS::BedrockAgentCore::Memory")
	some s in flatten_list(name, "Properties.MemoryStrategies")
	is_object(s.value)
	some kind, strat in s.value
	is_object(strat)
	ns := object.get(strat, "Namespaces", [])
	is_array(ns)
	count(ns) > 1
}
