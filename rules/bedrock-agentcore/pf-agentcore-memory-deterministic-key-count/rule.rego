package cdk_preflight

import rego.v1

# The schema allows 20 MetadataSchema entries per strategy; the dev guide
# (Deterministic metadata constraints) caps STRICTLY_CONSISTENT keys at 3 per
# strategy, and CreateMemory rejects the fourth. Counted per MemoryRecordSchema
# (the Reflection schemas of episodic strategies are not measured and skipped).
violation contains make_diag_full("pf-agentcore-memory-deterministic-key-count", "ERROR", name,
	sprintf("Properties.MemoryStrategies.%d.%s.MemoryRecordSchema.MetadataSchema", [sc.index, sc.kind]),
	sprintf("%s declares %d STRICTLY_CONSISTENT metadata keys; CreateMemory allows at most 3 per strategy", [sc.kind, n]),
	"Keep at most three keys with ExtractionType STRICTLY_CONSISTENT in a strategy; make the rest LLM_INFERRED",
	"https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/long-term-memory-metadata.html") if {
	some name in resources_of_type("AWS::BedrockAgentCore::Memory")
	some sc in _pf_acmem_schemas(name)
	sc.kind in _pf_acmem_det_kinds
	n := count([1 | some e in sc.entries; _pf_acmem_sc(e)])
	n > 3
}
