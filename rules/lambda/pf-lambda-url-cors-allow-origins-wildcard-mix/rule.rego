package cdk_preflight

import rego.v1

_pf_luco_fix := "Use either \"*\" alone or an explicit list of origins"

_pf_luco_url := "https://docs.aws.amazon.com/lambda/latest/dg/urls-configuration.html"

violation contains make_diag_full("pf-lambda-url-cors-allow-origins-wildcard-mix", "ERROR", name,
	"Properties.Cors.AllowOrigins",
	"'*' mixed with explicit entries in AllowOrigins; a browser accepts a single Access-Control-Allow-Origin value, so the wildcard cannot be combined with named origins",
	_pf_luco_fix, _pf_luco_url) if {
	some name in _pf_lam_url
	cors := _pf_lam_obj(_pf_lam_props(name), "Cors")
	vs := _pf_lam_list(object.get(cors, "AllowOrigins", []))
	"*" in vs
	count(vs) > 1
}
