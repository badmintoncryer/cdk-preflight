package cdk_preflight

import rego.v1

# MemoryExecutionRoleArn is optional in the schema, but CreateMemory rejects a
# memory that carries any CustomMemoryStrategy without it: "Please provide
# memoryExecutionRoleArn as memory contains one or more Custom strategies".
# Absence is proven on the preprocessed document (resolve() is undefined for
# both a missing key and an unresolvable value; see AGENTS.md).
_pf_memrole_absent(name) if {
	props := input.resources[name].properties
	is_object(props)
	object.get(props, "MemoryExecutionRoleArn", "__pf_absent") == "__pf_absent"
}

violation contains make_diag_full("pf-agentcore-memory-custom-strategy-execution-role", "ERROR", name,
	sprintf("Properties.MemoryStrategies.%d.CustomMemoryStrategy", [s.index]),
	"The memory has a CustomMemoryStrategy but no MemoryExecutionRoleArn; CreateMemory fails with \"Please provide memoryExecutionRoleArn as memory contains one or more Custom strategies\"",
	"Set MemoryExecutionRoleArn to a role that bedrock-agentcore.amazonaws.com can assume (with bedrock:InvokeModel for the strategy's models)",
	"https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/long-term-configuring-custom-strategies.html") if {
	some name in resources_of_type("AWS::BedrockAgentCore::Memory")
	_pf_memrole_absent(name)
	some s in flatten_list(name, "Properties.MemoryStrategies")
	is_object(object.get(s.value, "CustomMemoryStrategy", null))
}
