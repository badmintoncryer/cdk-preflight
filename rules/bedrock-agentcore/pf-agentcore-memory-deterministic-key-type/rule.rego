package cdk_preflight

import rego.v1

# MetadataSchema[].Type accepts STRING / STRINGLIST / NUMBER, but a key with
# ExtractionType STRICTLY_CONSISTENT must be STRING (dev guide, Deterministic
# metadata constraints); CreateMemory rejects any other type.
violation contains make_diag_full("pf-agentcore-memory-deterministic-key-type", "ERROR", name,
	sprintf("Properties.MemoryStrategies.%d.%s.MemoryRecordSchema.MetadataSchema.%d.Type", [sc.index, sc.kind, i]),
	sprintf("Metadata key '%s' is STRICTLY_CONSISTENT with Type %s; CreateMemory requires STRICTLY_CONSISTENT keys to be STRING", [e.Key, e.Type]),
	"Set Type to STRING, or use ExtractionType LLM_INFERRED for this key",
	"https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/long-term-memory-metadata.html") if {
	some name in resources_of_type("AWS::BedrockAgentCore::Memory")
	some sc in _pf_acmem_schemas(name)
	sc.kind in _pf_acmem_det_kinds
	some i, e in sc.entries
	_pf_acmem_sc(e)
	is_string(e.Type)
	e.Type != "STRING"
}
