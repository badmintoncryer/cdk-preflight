package cdk_preflight

import rego.v1

# Shared helpers for the CloudWatch Synthetics rules. Absence can only be proven on
# the preprocessed document (resolve() is undefined both for a missing key and for
# an unresolvable token, see AGENTS.md), so "is the property written" always goes
# through _pf_synlib_present / _pf_synlib_absent. Loaded ahead of every rule
# (BUNDLED_LIBS); never emits diagnostics.

_pf_synlib_props(name) := p if {
	p := input.resources[name].properties
	is_object(p)
}

# path is an array of keys, e.g. ["Code", "S3Key"].
_pf_synlib_present(name, path) if {
	object.get(_pf_synlib_props(name), path, "__pf_absent") != "__pf_absent"
}

_pf_synlib_absent(name, path) if {
	object.get(_pf_synlib_props(name), path, "__pf_absent") == "__pf_absent"
}

# The literal string the document carries at path, if it carries one. Undefined for a
# missing key and for a token ({"Ref": ...} is an object), which is what makes it safe
# to compare against an enum: resolve() hands back a logical id for a Ref-to-resource
# and would read as a bogus enum value. The default must not be a string - is_string()
# would accept the sentinel and the rule would fire on every resource that omits the key.
_pf_synlib_str(name, path) := v if {
	v := object.get(_pf_synlib_props(name), path, null)
	is_string(v)
}

# Schedule.Expression as [count, unit]. Undefined for cron(), for an unresolved token
# and for anything that is not exactly "rate(<digits> <word>)".
_pf_synlib_rate(expr) := [n, unit] if {
	is_string(expr)
	startswith(expr, "rate(")
	endswith(expr, ")")
	parts := split(substring(expr, 5, count(expr) - 6), " ")
	count(parts) == 2
	n := to_number(parts[0])
	unit := parts[1]
}

_pf_synlib_rate_units := {"minute", "minutes", "hour"}

_pf_synlib_rate_minutes(n, unit) := n if unit in {"minute", "minutes"}

_pf_synlib_rate_minutes(n, unit) := n * 60 if unit == "hour"

_pf_synlib_encryption_modes := {"SSE_S3", "SSE_KMS"}

# Does Code point at an S3 object at all? Its own rule body so that a caller never
# carries two `some .. in` iterations (two in one body take the whole pack down).
_pf_synlib_code_has_s3(name) if {
	some k in ["S3Bucket", "S3Key", "S3ObjectVersion"]
	_pf_synlib_present(name, ["Code", k])
}
