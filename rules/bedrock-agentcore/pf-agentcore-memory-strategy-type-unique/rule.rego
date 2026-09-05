package cdk_preflight

import rego.v1

# Nothing in the schema limits how many SemanticMemoryStrategy (or Summary /
# UserPreference / Episodic) entries a memory carries; CreateMemory allows one
# per type ("Only one strategy of each type is allowed"). Custom strategies
# are exempt (the error names the built-in types; not measured for Custom).
_pf_memstype_kinds(name) := [[s.index, kind] |
	some s in flatten_list(name, "Properties.MemoryStrategies")
	is_object(s.value)
	some kind, strat in s.value
	is_object(strat)
	kind != "CustomMemoryStrategy"
]

violation contains make_diag_full("pf-agentcore-memory-strategy-type-unique", "ERROR", name,
	sprintf("Properties.MemoryStrategies.%d.%s", [i, kind]),
	sprintf("More than one %s is declared; CreateMemory fails with \"Only one strategy of each type is allowed\"", [kind]),
	"Keep a single strategy per built-in type (use CustomMemoryStrategy for additional variants)",
	"https://docs.aws.amazon.com/bedrock-agentcore-control/latest/APIReference/API_MemoryStrategyInput.html") if {
	some name in resources_of_type("AWS::BedrockAgentCore::Memory")
	all := _pf_memstype_kinds(name)
	some [i, kind] in all
	count([1 | some [_, k] in all; k == kind]) > 1
	i == max([j | some [j, k] in all; k == kind])
}
