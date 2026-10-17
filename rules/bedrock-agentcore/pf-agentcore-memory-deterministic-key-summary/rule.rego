package cdk_preflight

import rego.v1

# SummaryMemoryStrategy carries the same MetadataSchema shape as the other
# strategies, but CreateMemory rejects ExtractionType STRICTLY_CONSISTENT on
# summary-based strategies (dev guide, Deterministic metadata constraints).
# The service message also names CustomMemoryStrategy with SummaryOverride;
# that branch is not measured and not checked here.
violation contains make_diag_full("pf-agentcore-memory-deterministic-key-summary", "ERROR", name,
	sprintf("Properties.MemoryStrategies.%d.SummaryMemoryStrategy.MemoryRecordSchema.MetadataSchema.%d.ExtractionType", [sc.index, i]),
	sprintf("Metadata key '%s' is STRICTLY_CONSISTENT in a SummaryMemoryStrategy; CreateMemory does not support STRICTLY_CONSISTENT on summary-based strategies", [object.get(e, "Key", "<unnamed>")]),
	"Use ExtractionType LLM_INFERRED in the summary strategy, or move the key to a semantic, user preference or episodic strategy",
	"https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/long-term-memory-metadata.html") if {
	some name in resources_of_type("AWS::BedrockAgentCore::Memory")
	some sc in _pf_acmem_schemas(name)
	sc.kind == "SummaryMemoryStrategy"
	some i, e in sc.entries
	_pf_acmem_sc(e)
}
