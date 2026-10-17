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

# ---- CapacityProvider / Runtime (Instances) helpers --------------------------

# Literal Volumes[].EbsConfiguration objects of a CapacityProvider with their
# index. Empty when Volumes is absent, a Ref, or carries Fn::If entries.
_pf_accp_vols(name) := [{"i": i, "ebs": v.EbsConfiguration} |
	l := _pf_ll_raw(name, "Properties.ComputeConfiguration.Ec2Configuration.Volumes")
	_pf_countable_items(l)
	some i, v in l
	is_object(v)
	is_object(object.get(v, "EbsConfiguration", null))
]

# Literal LaunchParameters.EphemeralVolumes entries with their index.
_pf_accp_ephemeral(name) := [{"i": i, "v": v} |
	l := _pf_ll_raw(name, "Properties.ComputeConfiguration.Ec2Configuration.LaunchTemplateSource.LaunchParameters.EphemeralVolumes")
	_pf_countable_items(l)
	some i, v in l
	is_object(v)
]

# The set of volume names a CapacityProvider defines, only when every name is
# known: Volumes absent ({}), or a literal list whose names are all strings.
_pf_accp_vol_names(name) := set() if {
	_pf_ll_raw(name, "Properties.ComputeConfiguration.Ec2Configuration.Volumes") == "__pf_absent"
}

_pf_accp_vol_names(name) := names if {
	l := _pf_ll_raw(name, "Properties.ComputeConfiguration.Ec2Configuration.Volumes")
	_pf_countable_items(l)
	vols := _pf_accp_vols(name)
	count(vols) == count(l)
	names := {n | some v in vols; n := object.get(v.ebs, "Name", null); is_string(n)}
	count([1 | some v in vols; is_string(object.get(v.ebs, "Name", null))]) == count(vols)
}

# A number property, or dflt when the property is absent.
_pf_acrt_num(name, path, dflt) := dflt if {
	_pf_ll_raw(name, path) == "__pf_absent"
}

_pf_acrt_num(name, path, _) := n if {
	n := resolve(name, path)
	is_number(n)
}

# The in-template CapacityProvider a Runtime points at (Ref / GetAtt).
_pf_acrt_cp(name) := _pf_bedrocklib_ref_target(
	resolve(name, "Properties.CapacityProviderConfiguration.CapacityProviderArn"),
	"AWS::BedrockAgentCore::CapacityProvider",
)

# Instances runtime: CapacityProviderConfiguration is present.
_pf_acrt_has_cp(name) if {
	_pf_ll_raw(name, "Properties.CapacityProviderConfiguration") != "__pf_absent"
}

# Literal FilesystemConfigurations entries with their index.
_pf_acrt_fs(name) := [{"i": i, "v": v} |
	l := _pf_ll_raw(name, "Properties.FilesystemConfigurations")
	_pf_countable_items(l)
	some i, v in l
	is_object(v)
]
