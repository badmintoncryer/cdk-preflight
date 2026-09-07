package cdk_preflight

import rego.v1

_pf_lppw_fix := "Remove the whitespace from Principal"

_pf_lppw_url := "https://docs.aws.amazon.com/lambda/latest/api/API_AddPermission.html"

violation contains make_diag_full("pf-lambda-perm-principal-whitespace", "ERROR", name,
	"Properties.Principal",
	sprintf("whitespace in principal '%v'; the CFN pattern ^.*$ accepts it but the API pattern [^\\s]+ rejects it", [v]),
	_pf_lppw_fix, _pf_lppw_url) if {
	some name in _pf_lam_perm
	v := resolve(name, "Properties.Principal")
	is_string(v)
	regex.match(`\s`, v)
}
