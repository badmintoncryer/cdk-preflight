package cdk_preflight

import rego.v1

_pf_lefnl_fix := "Use the function ARN, or shorten the name to 64 characters"

_pf_lefnl_url := "https://docs.aws.amazon.com/lambda/latest/api/API_CreateEventSourceMapping.html"

violation contains make_diag_full("pf-lambda-esm-function-name-bare-max-length", "ERROR", name,
	"Properties.FunctionName",
	sprintf("FunctionName is a bare name of %v characters; the unqualified form is limited to 64", [count(fn)]),
	_pf_lefnl_fix, _pf_lefnl_url) if {
	some name in _pf_lam_esm
	fn := resolve(name, "Properties.FunctionName")
	_pf_lam_lit(fn)
	not contains(fn, ":")
	count(fn) > 64
}
