package cdk_preflight

import rego.v1

# Shared helpers for the Athena rules: traversal of the raw document (resolve()
# cannot prove a key absent) and the nested configuration blocks the workgroup
# and data catalog rules read.
# Loaded ahead of every rule (BUNDLED_LIBS); never emits diagnostics.

# A user-written literal, not a Ref/GetAtt that resolve() turned into a logical id.
_pf_athlib_lit(v) if {
	is_string(v)
	not input.resources[v]
}

# Raw properties of a resource. The preprocessed document is the only place
# where "the key is absent" can be told apart from "the value is a token".
_pf_athlib_props(name) := p if {
	p := input.resources[name].properties
	is_object(p)
}

_pf_athlib_obj(o, k) := v if {
	is_object(o)
	v := object.get(o, k, null)
	is_object(v)
}

_pf_athlib_has(o, k) if {
	is_object(o)
	object.get(o, k, "__pf_absent") != "__pf_absent"
}

_pf_athlib_wgcfg(name) := c if c := _pf_athlib_obj(_pf_athlib_props(name), "WorkGroupConfiguration")

_pf_athlib_resultcfg(name) := c if c := _pf_athlib_obj(_pf_athlib_wgcfg(name), "ResultConfiguration")

# Parameters of a data catalog: an absent map reads as empty, so a rule that
# looks for a required key fires whether Parameters is missing or incomplete.
_pf_athlib_params(name) := p if {
	p := object.get(_pf_athlib_props(name), "Parameters", {})
	is_object(p)
}
