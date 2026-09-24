package cdk_preflight

import rego.v1

# Shared helpers for the AWS Config rules (rules/config/*). Loaded ahead of
# every rule (BUNDLED_LIBS); never emits diagnostics.
#
# Most Config constraints are combinations inside one nested object -- a
# recording group that has to agree with its recording strategy, a rule source
# whose owner decides which siblings are required. The engine's Rego has no
# walk builtin, so each level is read through its own helper.

_pf_cfglib_props(name) := p if {
	p := input.resources[name].properties
	is_object(p)
}

# A key that is present in the template, whatever its value resolves to.
# object.get on the preprocessed document is the only reliable absence proof:
# resolve() is undefined both for a missing key and for an unresolvable value.
_pf_cfglib_present(o, k) if {
	is_object(o)
	object.get(o, k, "__pf_absent") != "__pf_absent"
}

_pf_cfglib_obj(o, k) := v if {
	is_object(o)
	v := object.get(o, k, null)
	is_object(v)
}

_pf_cfglib_list(o, k) := v if {
	is_object(o)
	v := object.get(o, k, [])
	is_array(v)
}

# ---- ConfigurationRecorder -------------------------------------------------

_pf_cfglib_group(name) := g if g := _pf_cfglib_obj(_pf_cfglib_props(name), "RecordingGroup")

_pf_cfglib_all_supported(name) if object.get(_pf_cfglib_group(name), "AllSupported", false) == true

_pf_cfglib_uses_only(name, want) if {
	s := _pf_cfglib_obj(_pf_cfglib_group(name), "RecordingStrategy")
	object.get(s, "UseOnly", null) == want
}

_pf_cfglib_group_resource_types(name) := v if v := _pf_cfglib_list(_pf_cfglib_group(name), "ResourceTypes")

# ---- ConfigRule ------------------------------------------------------------

_pf_cfglib_source(name) := s if s := _pf_cfglib_obj(_pf_cfglib_props(name), "Source")

_pf_cfglib_owner(name) := o if {
	o := object.get(_pf_cfglib_source(name), "Owner", null)
	is_string(o)
}

_pf_cfglib_source_details(name) := v if v := _pf_cfglib_list(_pf_cfglib_source(name), "SourceDetails")

_pf_cfglib_scope(name) := s if s := _pf_cfglib_obj(_pf_cfglib_props(name), "Scope")

# ---- RemediationConfiguration ---------------------------------------------

_pf_cfglib_parameters(name) := p if p := _pf_cfglib_obj(_pf_cfglib_props(name), "Parameters")
