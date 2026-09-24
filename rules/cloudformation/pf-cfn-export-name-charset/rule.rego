package cdk_preflight

import rego.v1

# Export.Name is validated by CreateStack itself, never by the template schema:
# the bundled engine accepts any string here. The name is what the engine has
# already resolved, so Fn::Sub over pseudo parameters is compared as the string
# it becomes (stack names carry the same charset, so that substitution is safe).
_pf_cfnexpchar_bad contains [out, ename] if {
	some out, o in input.outputs
	ename := object.get(o, "exportName", null)
	is_string(ename)
	not regex.match(`^[A-Za-z0-9:-]+$`, ename)
}

violation contains make_diag_full("pf-cfn-export-name-charset", "ERROR", out,
	sprintf("Outputs.%s.Export.Name", [out]),
	sprintf("Export name '%s' uses characters outside [A-Za-z0-9:-]; CreateStack rejects the template with \"The Name field of every Export member must be specified and consist only of alphanumeric characters, colons, or hyphens.\"", [ename]),
	"Use only alphanumerics, colons and hyphens in Export.Name",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/outputs-section-structure.html") if {
	some [out, ename] in _pf_cfnexpchar_bad
}
