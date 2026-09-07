package cdk_preflight

import rego.v1

_pf_llpl_fix := "Shorten the layer name so the ARN fits in 140 characters"

_pf_llpl_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lambda-layerversionpermission.html"

violation contains make_diag_full("pf-lambda-layerperm-arn-length", "ERROR", name,
	"Properties.LayerVersionArn",
	sprintf("layer ARN of %v characters; the property stops at 140", [count(v)]),
	_pf_llpl_fix, _pf_llpl_url) if {
	some name in _pf_lam_layerperm
	v := resolve(name, "Properties.LayerVersionArn")
	is_string(v)
	count(v) > 140
}
