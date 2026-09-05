package cdk_preflight

import rego.v1

# The registry schema pins these unions with minProperties/maxProperties = 1;
# CloudFormation's early validation enforces them and the stack rolls back
# before any resource is touched. The bundled engine (1.7.0-beta) does not
# evaluate min/maxProperties, so the template passes synth.
_pf_memsone_url := "https://docs.aws.amazon.com/bedrock-agentcore-control/latest/APIReference/API_MemoryStrategyInput.html"

violation contains make_diag_full("pf-agentcore-memory-strategy-exactly-one", "ERROR", name,
	sprintf("Properties.MemoryStrategies.%d", [s.index]),
	sprintf("MemoryStrategies entry holds %d strategy types; exactly one is required and CloudFormation rejects the template (PROPERTY_VALIDATION: minimum size 1 / maximum size 1)", [count(s.value)]),
	"Put exactly one of SemanticMemoryStrategy, SummaryMemoryStrategy, UserPreferenceMemoryStrategy, EpisodicMemoryStrategy, or CustomMemoryStrategy in each entry",
	_pf_memsone_url) if {
	some name in resources_of_type("AWS::BedrockAgentCore::Memory")
	some s in flatten_list(name, "Properties.MemoryStrategies")
	is_object(s.value)
	count(s.value) != 1
}

violation contains make_diag_full("pf-agentcore-memory-strategy-exactly-one", "ERROR", name,
	sprintf("Properties.MemoryStrategies.%d.CustomMemoryStrategy.Configuration", [s.index]),
	sprintf("CustomMemoryStrategy.Configuration holds %d overrides; at most one is allowed and CloudFormation rejects the template (PROPERTY_VALIDATION: maximum size 1)", [count(cfg)]),
	"Keep a single override (SemanticOverride, SummaryOverride, UserPreferenceOverride, EpisodicOverride, or SelfManagedConfiguration) per custom strategy",
	_pf_memsone_url) if {
	some name in resources_of_type("AWS::BedrockAgentCore::Memory")
	some s in flatten_list(name, "Properties.MemoryStrategies")
	custom := object.get(s.value, "CustomMemoryStrategy", null)
	is_object(custom)
	cfg := object.get(custom, "Configuration", null)
	is_object(cfg)
	count(cfg) > 1
}
