package cdk_preflight

import rego.v1

_pf_lpue_fix := "Set FunctionUrlAuthType to AWS_IAM or NONE"

_pf_lpue_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lambda-permission.html"

violation contains make_diag_full("pf-lambda-perm-function-url-auth-type-enum", "ERROR", name,
	"Properties.FunctionUrlAuthType",
	sprintf("FunctionUrlAuthType '%v'; the condition key takes AWS_IAM or NONE", [v]),
	_pf_lpue_fix, _pf_lpue_url) if {
	some name in _pf_lam_perm
	v := resolve(name, "Properties.FunctionUrlAuthType")
	is_string(v)
	not v in {"AWS_IAM", "NONE"}
}
