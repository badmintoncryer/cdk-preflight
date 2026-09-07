package cdk_preflight

import rego.v1

_pf_lpua_fix := "Use Action lambda:InvokeFunctionUrl when FunctionUrlAuthType is set"

_pf_lpua_url := "https://docs.aws.amazon.com/lambda/latest/dg/urls-auth.html"

violation contains make_diag_full("pf-lambda-perm-url-auth-action", "ERROR", name,
	"Properties.Action",
	sprintf("FunctionUrlAuthType with action '%v'; the lambda:FunctionUrlAuthType condition key is only evaluated for lambda:InvokeFunctionUrl, so the statement never constrains anything", [a]),
	_pf_lpua_fix, _pf_lpua_url) if {
	some name in _pf_lam_perm
	props := _pf_lam_props(name)
	_pf_lam_has_key(props, "FunctionUrlAuthType")
	a := resolve(name, "Properties.Action")
	a != "lambda:InvokeFunctionUrl"
	not _pf_lam_has_key(props, "InvokedViaFunctionUrl")
}
