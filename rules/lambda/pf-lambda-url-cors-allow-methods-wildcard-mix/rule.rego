package cdk_preflight

import rego.v1

_pf_lucm_fix := "Use either \"*\" alone or an explicit list of methods"

_pf_lucm_url := "https://docs.aws.amazon.com/lambda/latest/api/API_Cors.html"

violation contains make_diag_full("pf-lambda-url-cors-allow-methods-wildcard-mix", "ERROR", name,
	"Properties.Cors.AllowMethods",
	"'*' mixed with explicit entries in AllowMethods; the wildcard already covers every method and the URL create rejects the mixed list",
	_pf_lucm_fix, _pf_lucm_url) if {
	some name in _pf_lam_url
	cors := _pf_lam_obj(_pf_lam_props(name), "Cors")
	vs := _pf_lam_list(object.get(cors, "AllowMethods", []))
	"*" in vs
	count(vs) > 1
}
