package cdk_preflight

import rego.v1

_pf_lpfl_fix := "Drop the :$LATEST qualifier, or name a published version or alias"

_pf_lpfl_url := "https://docs.aws.amazon.com/lambda/latest/api/API_AddPermission.html"

violation contains make_diag_full("pf-lambda-perm-function-name-latest", "ERROR", name,
	"Properties.FunctionName",
	"a :$LATEST qualifier; Lambda refuses to attach a resource policy to the unpublished version and the CFN pattern lets it through",
	_pf_lpfl_fix, _pf_lpfl_url) if {
	some name in _pf_lam_perm
	v := resolve(name, "Properties.FunctionName")
	is_string(v)
	endswith(v, ":$LATEST")
}
