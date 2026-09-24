package cdk_preflight

import rego.v1

# Export names are resolved before any resource exists, so Ref/GetAtt on a
# resource - and Fn::ImportValue - are rejected outright. A Ref to a *parameter*
# is legal, which is why this only fires on the markers that name a resource of
# this template or an import; a Sub/Join that wraps a resource ref collapses to
# an opaque marker and is deliberately left undetected.
_pf_cfnexpref_dep(e) := sprintf("resource %s", [ref]) if {
	object.get(e, "__kind", "") == "resource"
	ref := object.get(e, "__ref", "")
	input.resources[ref]
}

_pf_cfnexpref_dep(e) := sprintf("an attribute of resource %s", [ref]) if {
	startswith(object.get(e, "__kind", ""), "getatt:")
	ref := object.get(e, "__ref", "")
	input.resources[ref]
}

_pf_cfnexpref_dep(e) := "an imported value (Fn::ImportValue)" if {
	startswith(object.get(e, "__dynamic", ""), "cross-stack import")
}

_pf_cfnexpref_bad contains [out, dep] if {
	some out, o in input.outputs
	e := object.get(o, "exportName", null)
	is_object(e)
	dep := _pf_cfnexpref_dep(e)
}

violation contains make_diag_full("pf-cfn-export-name-resource-ref", "ERROR", out,
	sprintf("Outputs.%s.Export.Name", [out]),
	sprintf("This export name depends on %s; CreateStack rejects the template with \"The Name field of Export must not depend on any resources, imported values, or Fn::GetAZs.\"", [dep]),
	"Build the export name from literals, parameters and pseudo parameters only",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/intrinsic-function-reference-importvalue.html") if {
	some [out, dep] in _pf_cfnexpref_bad
}
