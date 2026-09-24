package cdk_preflight

import rego.v1

# The engine flattens every Fn::ImportValue into a marker string: a resolvable
# argument becomes "cross-stack import: <name>", an unresolvable one loses the
# name. A parameter with no default is unresolvable too and is perfectly legal,
# so the nameless marker alone is not enough. Fire only when the resource also
# carries a Ref/GetAtt at a *resource* of this template whose own marker is
# absent from the properties - i.e. that reference was swallowed by the import.
_pf_cfnivref_marker(r) := sprintf(`{"__kind":"getatt:%s","__ref":"%s"}`, [object.get(r, "attr", ""), r.target]) if {
	object.get(r, "kind", "") == "GetAtt"
}

_pf_cfnivref_marker(r) := sprintf(`{"__kind":"resource","__ref":"%s"}`, [r.target]) if {
	object.get(r, "kind", "") == "Ref"
}

_pf_cfnivref_bad contains [name, target] if {
	some name, res in input.resources
	props := json.marshal(object.get(res, "properties", {}))
	contains(props, `{"__dynamic":"cross-stack import","__param_type"`)
	some ref in object.get(res, "outgoingRefs", [])
	target := ref.target
	input.resources[target]
	not contains(props, _pf_cfnivref_marker(ref))
}

violation contains make_diag_full("pf-cfn-importvalue-resource-ref", "ERROR", name,
	"Properties",
	sprintf("An Fn::ImportValue on this resource takes its export name from resource %s; CreateStack rejects the template with \"the attribute in Fn::ImportValue must not depend on any resources, imported values, or Fn::GetAZs\"", [target]),
	"Pass Fn::ImportValue a literal, a parameter or a pseudo parameter - never a Ref/GetAtt on a resource",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/intrinsic-function-reference-importvalue.html") if {
	some [name, target] in _pf_cfnivref_bad
}
