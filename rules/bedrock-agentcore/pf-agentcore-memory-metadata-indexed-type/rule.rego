package cdk_preflight

import rego.v1

# IndexedKeys and each strategy's MetadataSchema declare a Type per key
# independently. When a schema key is also an indexed key, CreateMemory
# requires the two Types to match ("Type mismatch for indexed key"). Keys are
# matched exactly here (case folding would only add findings).
violation contains make_diag_full("pf-agentcore-memory-metadata-indexed-type", "ERROR", name,
	sprintf("Properties.MemoryStrategies.%d.%s.MemoryRecordSchema.MetadataSchema.%d.Type", [sc.index, sc.kind, i]),
	sprintf("Metadata key '%s' has Type %s but IndexedKeys declares it as %s; CreateMemory rejects the type mismatch", [e.Key, e.Type, ik.Type]),
	"Use the same Type for the key in IndexedKeys and in every strategy MetadataSchema",
	"https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/long-term-memory-metadata.html") if {
	some name in resources_of_type("AWS::BedrockAgentCore::Memory")
	idx := _pf_acmem_indexed(name)
	some sc in _pf_acmem_schemas(name)
	some i, e in sc.entries
	is_string(object.get(e, "Key", null))
	is_string(object.get(e, "Type", null))
	some ik in idx
	object.get(ik, "Key", null) == e.Key
	is_string(object.get(ik, "Type", null))
	ik.Type != e.Type
}
