package cdk_preflight

import rego.v1

_pf_ladwr_fix := "Use a FunctionWeight between 0.0 and 1.0"

_pf_ladwr_url := "https://docs.aws.amazon.com/lambda/latest/api/API_AliasRoutingConfiguration.html"

violation contains make_diag_full("pf-lambda-alias-version-weight-range", "ERROR", name,
	"Properties.RoutingConfig.AdditionalVersionWeights",
	sprintf("routing weight %v; FunctionWeight is the fraction of traffic sent to the additional version and has to be between 0.0 and 1.0", [wt]),
	_pf_ladwr_fix, _pf_ladwr_url) if {
	some name in _pf_lam_alias
	props := _pf_lam_props(name)
	rc := _pf_lam_obj(props, "RoutingConfig")
	ws := _pf_lam_list(object.get(rc, "AdditionalVersionWeights", []))
	some w in ws
	is_object(w)
	wt := to_number(object.get(w, "FunctionWeight", 0))
	_pf_ladwr_out(wt)
}

_pf_ladwr_out(wt) if wt < 0

_pf_ladwr_out(wt) if wt > 1
