package cdk_preflight

import rego.v1

_pf_ladvm_fix := "Keep a single entry in AdditionalVersionWeights"

_pf_ladvm_url := "https://docs.aws.amazon.com/lambda/latest/dg/configuring-alias-routing.html"

violation contains make_diag_full("pf-lambda-alias-additional-versions-max-one", "ERROR", name,
	"Properties.RoutingConfig.AdditionalVersionWeights",
	sprintf("%v routing entries; an alias resolves to at most two versions, so AdditionalVersionWeights takes a single entry", [count(ws)]),
	_pf_ladvm_fix, _pf_ladvm_url) if {
	some name in _pf_lam_alias
	props := _pf_lam_props(name)
	rc := _pf_lam_obj(props, "RoutingConfig")
	ws := _pf_lam_list(object.get(rc, "AdditionalVersionWeights", []))
	count(ws) > 1
}
