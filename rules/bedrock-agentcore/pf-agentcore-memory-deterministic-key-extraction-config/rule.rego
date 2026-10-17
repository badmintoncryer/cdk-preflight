package cdk_preflight

import rego.v1

# ExtractionConfig is optional on every MetadataSchema entry, but a key with
# ExtractionType STRICTLY_CONSISTENT takes its value from the event, and
# CreateMemory rejects an ExtractionConfig on it (dev guide, Deterministic
# metadata constraints).
violation contains make_diag_full("pf-agentcore-memory-deterministic-key-extraction-config", "ERROR", name,
	sprintf("Properties.MemoryStrategies.%d.%s.MemoryRecordSchema.MetadataSchema.%d.ExtractionConfig", [sc.index, sc.kind, i]),
	sprintf("Metadata key '%s' is STRICTLY_CONSISTENT and also sets ExtractionConfig; CreateMemory rejects extractionConfig on STRICTLY_CONSISTENT keys", [object.get(e, "Key", "<unnamed>")]),
	"Remove ExtractionConfig from the key, or switch it to ExtractionType LLM_INFERRED",
	"https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/long-term-memory-metadata.html") if {
	some name in resources_of_type("AWS::BedrockAgentCore::Memory")
	some sc in _pf_acmem_schemas(name)
	sc.kind in _pf_acmem_det_kinds
	some i, e in sc.entries
	_pf_acmem_sc(e)
	object.get(e, "ExtractionConfig", "__pf_absent") != "__pf_absent"
}
