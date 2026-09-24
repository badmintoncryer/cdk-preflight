package cdk_preflight

import rego.v1

# Shared helpers for the AWS Global Accelerator rules. Listener and EndpointGroup
# reach their parent only through an ARN property (Ref returns the parent's ARN for
# all three resource types), so every cross-resource rule here needs the same
# reference resolution and the same port-range parsing.
# Loaded ahead of every rule (BUNDLED_LIBS); never emits diagnostics.

_pf_galib_props(name) := p if {
	p := input.resources[name].properties
	is_object(p)
}

# Absence has to be proven against the raw document: resolve() cannot tell
# "absent" from "unresolvable".
_pf_galib_absent(name, key) if {
	object.get(object.get(input.resources[name], "properties", {}), key, "__pf_absent") == "__pf_absent"
}

_pf_galib_oget(o, k) := v if {
	is_object(o)
	v := object.get(o, k, "__pf_absent")
	v != "__pf_absent"
}

_pf_galib_get(name, k) := _pf_galib_oget(_pf_galib_props(name), k)

_pf_galib_str(name, k) := v if {
	v := resolve(name, sprintf("Properties.%s", [k]))
	is_string(v)
}

# A user-written literal, not a Ref/GetAtt that resolve() turned into a logical id.
_pf_galib_lit(v) if {
	is_string(v)
	not input.resources[v]
}

# CloudFormation accepts "true" for a boolean property just as it accepts true.
_pf_galib_true(v) if v == true

_pf_galib_true(v) if v == "true"

# Ports arrive as numbers in JSON templates and as numeric strings when a
# template was written by hand; tokens and Refs stay undefined.
_pf_galib_int(v) := v if is_number(v)

_pf_galib_int(v) := n if {
	is_string(v)
	regex.match(`^[0-9]+$`, v)
	n := to_number(v)
}

_pf_galib_listeners := resources_of_type("AWS::GlobalAccelerator::Listener")

_pf_galib_groups := resources_of_type("AWS::GlobalAccelerator::EndpointGroup")

# Logical id of the in-template resource of `type` that an ARN property points at.
_pf_galib_target(name, path, type) := t if {
	t := resolve(name, path)
	is_string(t)
	t in resources_of_type(type)
}

# The Accelerator a Listener hangs off.
_pf_galib_accel(l) := _pf_galib_target(l, "Properties.AcceleratorArn", "AWS::GlobalAccelerator::Accelerator")

# The Listener an EndpointGroup hangs off.
_pf_galib_listener(g) := _pf_galib_target(g, "Properties.ListenerArn", "AWS::GlobalAccelerator::Listener")

# [FromPort, ToPort] of every well-formed PortRange on a listener.
_pf_galib_ranges(l) := [[f, t] |
	some r in flatten_list(l, "Properties.PortRanges")
	f := _pf_galib_int(_pf_galib_oget(r.value, "FromPort"))
	t := _pf_galib_int(_pf_galib_oget(r.value, "ToPort"))
]

# True when port p falls inside one of listener l's port ranges.
_pf_galib_in_ranges(l, p) if {
	some r in _pf_galib_ranges(l)
	p >= r[0]
	p <= r[1]
}

# The full AWS Region list lives in rules/_lib/route53.rego; Global Accelerator
# validates EndpointGroupRegion against the same set of Region codes, so the
# table is shared rather than copied.
# ponytail: static table, so a Region newer than the table reads as a typo.
_pf_galib_regions := _pf_r53_regions
