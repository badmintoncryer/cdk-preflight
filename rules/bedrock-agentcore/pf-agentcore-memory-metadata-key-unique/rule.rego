package cdk_preflight

import rego.v1

# Neither MetadataSchema nor IndexedKeys is keyed by Key in the schema, so
# duplicates pass every static layer. CreateMemory rejects a key repeated in
# one strategy's MetadataSchema ("Duplicate metadata keys") and an indexed key
# repeated in IndexedKeys ("Duplicate indexed key names (case-insensitive)").
# Both compare ignoring case: bench 2026-10-17 rejected MetadataSchema keys
# 'a' and 'A' as duplicates.
violation contains make_diag_full("pf-agentcore-memory-metadata-key-unique", "ERROR", name,
	sprintf("Properties.MemoryStrategies.%d.%s.MemoryRecordSchema.MetadataSchema.%d.Key", [sc.index, sc.kind, i]),
	sprintf("Metadata key '%s' appears more than once in the %s schema (names are compared ignoring case); CreateMemory rejects duplicate metadata keys", [e.Key, sc.kind]),
	"Declare each metadata key once per strategy; names that differ only in case count as the same key",
	"https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/long-term-memory-metadata.html") if {
	some name in resources_of_type("AWS::BedrockAgentCore::Memory")
	some sc in _pf_acmem_schemas(name)
	some i, e in sc.entries
	is_string(object.get(e, "Key", null))
	some j, e2 in sc.entries
	j < i
	k2 := object.get(e2, "Key", null)
	is_string(k2)
	lower(k2) == lower(e.Key)
}

violation contains make_diag_full("pf-agentcore-memory-metadata-key-unique", "ERROR", name,
	sprintf("Properties.IndexedKeys.%d.Key", [i]),
	sprintf("Indexed key '%s' is declared more than once (names are compared ignoring case); CreateMemory rejects duplicate indexed key names", [ik.Key]),
	"Declare each indexed key once; names that differ only in case count as the same key",
	"https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/long-term-memory-metadata.html") if {
	some name in resources_of_type("AWS::BedrockAgentCore::Memory")
	idx := _pf_acmem_indexed(name)
	some i, ik in idx
	is_string(object.get(ik, "Key", null))
	some j, ik2 in idx
	j < i
	k2 := object.get(ik2, "Key", null)
	is_string(k2)
	lower(k2) == lower(ik.Key)
}
