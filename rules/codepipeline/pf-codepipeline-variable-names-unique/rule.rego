package cdk_preflight

import rego.v1

# The engine's F3037 dedupes whole list elements; two variables that share a name
# but differ in DefaultValue are distinct elements, so only the service sees it.
violation contains make_diag_full("pf-codepipeline-variable-names-unique", "ERROR", name,
	sprintf("Properties.Variables.%v.Name", [vj]),
	sprintf("variable name '%v' is used by entries %d and %d; CreatePipeline fails with \"InvalidStructureException: Variable names must be unique. The following variable name is already in use: %v\"", [vn, vi, vj, vn]),
	"Give every pipeline variable a distinct name",
	"https://docs.aws.amazon.com/codepipeline/latest/userguide/pipeline-types.html") if {
	some name in resources_of_type("AWS::CodePipeline::Pipeline")
	vars := object.get(_pf_cplib_props(name), "Variables", [])
	some vi, v in vars
	some vj, v2 in vars
	vi < vj
	vn := _pf_cplib_get(v, "Name")
	_pf_cplib_lit(vn)
	vn == _pf_cplib_get(v2, "Name")
}
