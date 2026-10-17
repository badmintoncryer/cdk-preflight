package cdk_preflight

import rego.v1

# Shared helpers for the AWS::BedrockAgentCore::Memory metadata rules.
# Never emits diagnostics.

_pf_acmem_kinds := {
	"SemanticMemoryStrategy", "SummaryMemoryStrategy", "UserPreferenceMemoryStrategy",
	"EpisodicMemoryStrategy", "CustomMemoryStrategy",
}

# Strategy kinds on which STRICTLY_CONSISTENT keys are allowed at all.
_pf_acmem_det_kinds := _pf_acmem_kinds - {"SummaryMemoryStrategy"}

# Each strategy's top-level MemoryRecordSchema.MetadataSchema, when it is a
# literal list with no conditional entries. The Reflection schemas of episodic
# strategies are not measured and not returned.
_pf_acmem_schemas(name) := [{"index": s.index, "kind": kind, "entries": e} |
	some s in flatten_list(name, "Properties.MemoryStrategies")
	is_object(s.value)
	some kind, strat in s.value
	kind in _pf_acmem_kinds
	is_object(strat)
	rs := object.get(strat, "MemoryRecordSchema", {})
	is_object(rs)
	e := object.get(rs, "MetadataSchema", [])
	_pf_countable_items(e)
]

# IndexedKeys as a literal list ([] when absent). Undefined when it is a Ref,
# Fn::If or carries conditional entries, so absence cannot be proven.
_pf_acmem_indexed(name) := [] if {
	_pf_ll_raw(name, "Properties.IndexedKeys") == "__pf_absent"
}

_pf_acmem_indexed(name) := l if {
	l := _pf_ll_raw(name, "Properties.IndexedKeys")
	_pf_countable_items(l)
}

_pf_acmem_sc(e) if {
	is_object(e)
	object.get(e, "ExtractionType", null) == "STRICTLY_CONSISTENT"
}
