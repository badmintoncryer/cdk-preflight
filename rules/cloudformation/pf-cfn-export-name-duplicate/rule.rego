package cdk_preflight

import rego.v1

# Export names must be unique inside the template as well as inside the account.
# The in-template collision is the half no other layer sees: the engine reads
# Outputs but never compares two of them.
_pf_cfnexpdup_bad contains [out, ename] if {
	some out, o in input.outputs
	ename := object.get(o, "exportName", null)
	is_string(ename)
	some other, o2 in input.outputs
	other != out
	object.get(o2, "exportName", null) == ename
}

violation contains make_diag_full("pf-cfn-export-name-duplicate", "ERROR", out,
	sprintf("Outputs.%s.Export.Name", [out]),
	sprintf("Export name '%s' is declared by more than one output; CreateStack rejects the template with \"The Outputs section contains duplicate Export names: [%s]. Specify a unique name for each export.\"", [ename, ename]),
	"Give each exported output its own export name",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/outputs-section-structure.html") if {
	some [out, ename] in _pf_cfnexpdup_bad
}
