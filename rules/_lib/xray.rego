package cdk_preflight

import rego.v1

# Shared helpers for the X-Ray rules (rules/xray/pf-xray-*).
# Loaded ahead of every rule (BUNDLED_LIBS); never emits diagnostics.
#
# Absence can only be proven on the preprocessed document (resolve() is undefined
# both for a missing key and for an unresolvable token, see AGENTS.md), so every
# "is this written" question goes through object.get on input.resources.

_pf_xraylib_props(name) := p if {
	p := object.get(input.resources[name], "properties", {})
	is_object(p)
}

_pf_xraylib_has(o, k) if {
	object.get(o, k, "__pf_absent") != "__pf_absent"
}

# The SamplingRule entity of an AWS::XRay::SamplingRule resource.
_pf_xraylib_sr(name) := sr if {
	sr := object.get(_pf_xraylib_props(name), "SamplingRule", null)
	is_object(sr)
}

# True only when the document literally says true (an unresolved token is neither).
_pf_xraylib_true(v) if v == true

_pf_xraylib_true(v) if v == "true"

# The PolicyDocument of an AWS::XRay::ResourcePolicy, as written: a JSON string.
_pf_xraylib_policy(name) := s if {
	s := object.get(_pf_xraylib_props(name), "PolicyDocument", null)
	is_string(s)
}

# Statements of a parsed policy document as [index, statement]; a lone object is 0.
_pf_xraylib_stmts(doc) := [[0, s]] if {
	s := object.get(doc, "Statement", null)
	is_object(s)
}

_pf_xraylib_stmts(doc) := out if {
	arr := object.get(doc, "Statement", null)
	is_array(arr)
	out := [[i, s] | some i, s in arr]
}

# A scalar-or-list policy value as a list.
_pf_xraylib_list(v) := [v] if is_string(v)

_pf_xraylib_list(v) := v if is_array(v)
