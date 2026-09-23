package cdk_preflight

import rego.v1

# Shared helpers for the Redshift (provisioned) rules. Absence can only be proven on
# input.resources (resolve() is undefined both for a missing key and for an unresolved
# token, see AGENTS.md), so "is the property written" always goes through _pf_redshiftlib_has.
# Node-type comparisons are literal-only (a Ref resolves to a logical id, not a node type).
# Never emits diagnostics (BUNDLED_LIBS).

_pf_redshiftlib_props(name) := p if {
	p := input.resources[name].properties
	is_object(p)
}

_pf_redshiftlib_get(name, k) := v if {
	v := object.get(_pf_redshiftlib_props(name), k, "__pf_absent")
	v != "__pf_absent"
}

_pf_redshiftlib_has(name, k) if {
	_pf_redshiftlib_get(name, k)
}

# True only when the document literally says true (unresolved tokens are not judged).
_pf_redshiftlib_true(name, k) if _pf_redshiftlib_get(name, k) == true

_pf_redshiftlib_true(name, k) if _pf_redshiftlib_get(name, k) == "true"

# Absent, or literally false. An unresolved token is neither, so rules that need
# "not enabled" use this instead of `not _pf_redshiftlib_true` to stay token-safe.
_pf_redshiftlib_false_or_absent(name, k) if not _pf_redshiftlib_has(name, k)

_pf_redshiftlib_false_or_absent(name, k) if _pf_redshiftlib_get(name, k) == false

_pf_redshiftlib_false_or_absent(name, k) if _pf_redshiftlib_get(name, k) == "false"

# A user literal: a string that is not the logical id a Ref/GetAtt resolves to.
_pf_redshiftlib_lit(v) if {
	is_string(v)
	not input.resources[v]
}

# Literal string property; undefined for tokens, refs and absent keys.
_pf_redshiftlib_str(name, k) := v if {
	v := resolve(name, sprintf("Properties.%s", [k]))
	_pf_redshiftlib_lit(v)
}

# Numeric property; undefined when absent or unresolvable (to_number(null) would be 0).
_pf_redshiftlib_num(name, k) := n if {
	v := resolve(name, sprintf("Properties.%s", [k]))
	v != null
	n := to_number(v)
}

# Lower-cased literal NodeType ("ra3.large"), and its family ("ra3" / "rg" / "dc2" / "ds2").
_pf_redshiftlib_node_type(name) := lower(v) if {
	v := _pf_redshiftlib_str(name, "NodeType")
}

_pf_redshiftlib_family(name) := f if {
	parts := split(_pf_redshiftlib_node_type(name), ".")
	count(parts) == 2
	f := parts[0]
}

# Families on Redshift Managed Storage: the ones that take the 5431-5455 / 8191-8215 port
# bands, AZ relocation, Multi-AZ, and that cannot disable automated snapshots.
_pf_redshiftlib_rms_families := {"ra3", "rg"}

_pf_redshiftlib_rms(name) if {
	_pf_redshiftlib_family(name) in _pf_redshiftlib_rms_families
}

_pf_redshiftlib_dc2(name) if _pf_redshiftlib_family(name) == "dc2"

# Lower-cased literal ClusterType ("single-node" / "multi-node").
_pf_redshiftlib_cluster_type(name) := lower(v) if {
	v := _pf_redshiftlib_str(name, "ClusterType")
}
