package cdk_preflight

import rego.v1

# Shared helpers for the AWS Glue rules. Absence is proven against the raw
# document (resolve() cannot tell "absent" from "unresolvable"), string values
# are guarded so a Ref/GetAtt resolved to a logical id is never compared against
# a literal, and numbers go through to_number so tokens skip instead of firing.
# Loaded ahead of every rule (BUNDLED_LIBS); never emits diagnostics.

_pf_gluelib_props(name) := p if {
	p := input.resources[name].properties
	is_object(p)
}

# Absent-safe object access; undefined when the key is missing.
_pf_gluelib_get(name, k) := v if {
	p := _pf_gluelib_props(name)
	v := object.get(p, k, "__pf_absent")
	v != "__pf_absent"
}

_pf_gluelib_has(name, k) if {
	_pf_gluelib_get(name, k)
}

_pf_gluelib_absent(name, k) if {
	p := _pf_gluelib_props(name)
	object.get(p, k, "__pf_absent") == "__pf_absent"
}

# A user-written literal, not a Ref/GetAtt that resolve() turned into a logical id.
_pf_gluelib_lit(v) if {
	is_string(v)
	not input.resources[v]
}

_pf_gluelib_str(name, path) := v if {
	v := resolve(name, path)
	_pf_gluelib_lit(v)
}

_pf_gluelib_num(name, path) := n if {
	n := to_number(resolve(name, path))
}

# The job flavour every combination rule keys on.
_pf_gluelib_command_name(name) := _pf_gluelib_str(name, "Properties.Command.Name")

_pf_gluelib_worker_type(name) := _pf_gluelib_str(name, "Properties.WorkerType")

_pf_gluelib_glue_version(name) := _pf_gluelib_str(name, "Properties.GlueVersion")
