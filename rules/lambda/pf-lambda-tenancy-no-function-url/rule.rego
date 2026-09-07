package cdk_preflight

import rego.v1

_pf_ltnu_fix := "Drop the AWS::Lambda::Url, or drop TenancyConfig"

_pf_ltnu_url := "https://docs.aws.amazon.com/lambda/latest/dg/tenant-isolation.html"

violation contains make_diag_full("pf-lambda-tenancy-no-function-url", "ERROR", uname,
	"Properties.TargetFunctionArn",
	"a function URL on a tenant-isolated function; the URL endpoint carries no tenant and the pair is rejected",
	_pf_ltnu_fix, _pf_ltnu_url) if {
	some fname in _pf_lam_fn
	_pf_lam_has(fname, "TenancyConfig")
	some uname in _pf_lam_url
	_pf_lam_ref(object.get(_pf_lam_props(uname), "TargetFunctionArn", {})) == fname
}
