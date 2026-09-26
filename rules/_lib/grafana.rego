package cdk_preflight

import rego.v1

# ---- AWS::Grafana::Workspace ------------------------------------------------

# The properties of a workspace. Always an object, so callers reach into it with
# object.get and the "__pf_absent" sentinel: a conditionally required property is
# read by comparing against that sentinel rather than by negating a helper, which
# would read as true on every template that builds the property from an intrinsic
# (#268 / #280).
_pf_grafana_props(name) := props if {
	props := input.resources[name].properties
	is_object(props)
}

# The literal strings in an array-valued property of `container`. An absent
# property, an Fn::If / Ref marker landing where the list should be, and a
# non-string element each yield nothing, so every rule built on this errs toward
# silence rather than a false positive.
_pf_grafana_strings(container, key) := [v |
	list := object.get(container, key, [])
	is_array(list)
	some v in list
	is_string(v)
]
