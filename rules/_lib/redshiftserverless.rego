package cdk_preflight

import rego.v1

# Shared helpers for the Redshift Serverless rules. Absence can only be proven on
# the preprocessed document (resolve() is undefined both for a missing key and for
# an unresolvable token, see AGENTS.md), so "is the property written" always goes
# through _pf_rsslib_has. Loaded ahead of every rule (BUNDLED_LIBS); never emits
# diagnostics.

_pf_rsslib_props(name) := p if {
	p := input.resources[name].properties
	is_object(p)
}

_pf_rsslib_has(name, k) if {
	object.get(_pf_rsslib_props(name), k, "__pf_absent") != "__pf_absent"
}

_pf_rsslib_get(name, k) := v if {
	v := object.get(_pf_rsslib_props(name), k, "__pf_absent")
	v != "__pf_absent"
}

# True only when the document literally says true (an unresolved token is neither).
_pf_rsslib_true(name, k) if _pf_rsslib_get(name, k) == true

_pf_rsslib_true(name, k) if _pf_rsslib_get(name, k) == "true"

_pf_rsslib_false(name, k) if _pf_rsslib_get(name, k) == false

_pf_rsslib_false(name, k) if _pf_rsslib_get(name, k) == "false"

# A list element as flatten_list hands it over: a literal string, or the marker
# object of a Ref / GetAtt, which carries the target's logical id in __ref.
_pf_rsslib_ref(v) := v if is_string(v)

_pf_rsslib_ref(v) := r if {
	is_object(v)
	r := object.get(v, "__ref", null)
	is_string(r)
}
