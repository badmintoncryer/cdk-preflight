package cdk_preflight

import rego.v1

# 256 characters, measured on the resolved name. count() counts code points;
# the charset the service allows for export names is ASCII, so that is bytes.
_pf_cfnexpmax_bad contains [out, n] if {
	some out, o in input.outputs
	ename := object.get(o, "exportName", null)
	is_string(ename)
	n := count(ename)
	n > 256
}

violation contains make_diag_full("pf-cfn-export-name-max", "ERROR", out,
	sprintf("Outputs.%s.Export.Name", [out]),
	sprintf("This export name is %d characters; CreateStack rejects the template with \"The Name field of every Export member must not be longer than 256 characters.\"", [n]),
	"Shorten the export name to 256 characters or fewer",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/outputs-section-structure.html") if {
	some [out, n] in _pf_cfnexpmax_bad
}
