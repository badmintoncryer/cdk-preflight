package cdk_preflight

import rego.v1

_pf_llpv_fix := "Use the versioned layer ARN (…:layer:<name>:<version>)"

_pf_llpv_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lambda-layerversionpermission.html"

violation contains make_diag_full("pf-lambda-layerperm-arn-version-suffix", "ERROR", name,
	"Properties.LayerVersionArn",
	sprintf("layer ARN '%v' has no version suffix; a permission is granted on one layer version, not on the layer as a whole", [v]),
	_pf_llpv_fix, _pf_llpv_url) if {
	some name in _pf_lam_layerperm
	v := resolve(name, "Properties.LayerVersionArn")
	parts := _pf_lam_arn(v)
	parts[2] == "lambda"
	count(split(parts[5], ":")) < 3
}
