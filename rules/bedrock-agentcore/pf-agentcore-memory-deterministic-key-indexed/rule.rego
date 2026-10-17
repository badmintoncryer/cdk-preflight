package cdk_preflight

import rego.v1

# Nothing ties MetadataSchema keys to IndexedKeys in the schema, but a
# STRICTLY_CONSISTENT key must be declared in the memory's IndexedKeys (dev
# guide, Deterministic metadata constraints). Keys are compared ignoring case
# (the service compares indexed key names case-insensitively), and the check
# steps back when IndexedKeys is not a literal list of literal keys.
violation contains make_diag_full("pf-agentcore-memory-deterministic-key-indexed", "ERROR", name,
	sprintf("Properties.MemoryStrategies.%d.%s.MemoryRecordSchema.MetadataSchema.%d.Key", [sc.index, sc.kind, i]),
	sprintf("Metadata key '%s' is STRICTLY_CONSISTENT but is not in the memory's IndexedKeys; CreateMemory requires it to be an indexed key", [e.Key]),
	"Add the key to IndexedKeys (Type STRING), or use ExtractionType LLM_INFERRED",
	"https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/long-term-memory-metadata.html") if {
	some name in resources_of_type("AWS::BedrockAgentCore::Memory")
	idx := _pf_acmem_indexed(name)
	every ik in idx {
		is_string(object.get(ik, "Key", null))
	}
	names := {lower(ik.Key) | some ik in idx}
	some sc in _pf_acmem_schemas(name)
	sc.kind in _pf_acmem_det_kinds
	some i, e in sc.entries
	_pf_acmem_sc(e)
	is_string(e.Key)
	not lower(e.Key) in names
}
