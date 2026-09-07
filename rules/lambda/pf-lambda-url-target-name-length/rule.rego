package cdk_preflight

import rego.v1

_pf_lutn_fix := "Use the function ARN, or a name of 64 characters or fewer"

_pf_lutn_url := "https://docs.aws.amazon.com/lambda/latest/api/API_CreateFunctionUrlConfig.html"

violation contains make_diag_full("pf-lambda-url-target-name-length", "ERROR", name,
	"Properties.TargetFunctionArn",
	sprintf("bare function name of %v characters; only the ARN form may be longer, the name form stops at 64", [count(v)]),
	_pf_lutn_fix, _pf_lutn_url) if {
	some name in _pf_lam_url
	v := resolve(name, "Properties.TargetFunctionArn")
	is_string(v)
	not startswith(v, "arn:")
	count(v) > 64
}
