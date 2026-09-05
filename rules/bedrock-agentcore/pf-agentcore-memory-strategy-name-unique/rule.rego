package cdk_preflight

import rego.v1

# Each MemoryStrategies[] entry is a one-key union (SemanticMemoryStrategy,
# SummaryMemoryStrategy, UserPreferenceMemoryStrategy, EpisodicMemoryStrategy,
# CustomMemoryStrategy) carrying a Name. The schema validates each Name's
# pattern but not uniqueness; CreateMemory rejects duplicates with
# "Duplicate memory strategy names were provided: [...]".
_pf_memsname_names(name) := [[s.index, n] |
	some s in flatten_list(name, "Properties.MemoryStrategies")
	is_object(s.value)
	some _, strat in s.value
	is_object(strat)
	n := object.get(strat, "Name", null)
	is_string(n)
]

violation contains make_diag_full("pf-agentcore-memory-strategy-name-unique", "ERROR", name,
	sprintf("Properties.MemoryStrategies.%d", [i]),
	sprintf("Memory strategy name '%s' is used more than once; CreateMemory fails with \"Duplicate memory strategy names were provided\"", [n]),
	"Give every memory strategy a distinct Name",
	"https://docs.aws.amazon.com/bedrock-agentcore-control/latest/APIReference/API_MemoryStrategyInput.html") if {
	some name in resources_of_type("AWS::BedrockAgentCore::Memory")
	all := _pf_memsname_names(name)
	some [i, n] in all
	count([1 | some [_, m] in all; m == n]) > 1
	i == max([j | some [j, m] in all; m == n])
}
