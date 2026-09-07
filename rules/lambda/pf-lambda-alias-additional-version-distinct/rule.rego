package cdk_preflight

import rego.v1

_pf_ladvd_fix := "Point AdditionalVersionWeights at a version other than the one in FunctionVersion"

_pf_ladvd_url := "https://docs.aws.amazon.com/lambda/latest/dg/configuring-alias-routing.html"

violation contains make_diag_full("pf-lambda-alias-additional-version-distinct", "ERROR", name,
	"Properties.RoutingConfig.AdditionalVersionWeights",
	"a routing entry that names the same version as the alias itself; a weighted alias splits traffic between two distinct versions and the create is rejected when both sides are the same",
	_pf_ladvd_fix, _pf_ladvd_url) if {
	some name in _pf_lam_alias
	props := _pf_lam_props(name)
	rc := _pf_lam_obj(props, "RoutingConfig")
	ws := _pf_lam_list(object.get(rc, "AdditionalVersionWeights", []))
	base := object.get(props, "FunctionVersion", "__pf_absent")
	some w in ws
	is_object(w)
	object.get(w, "FunctionVersion", "__pf_other") == base
}
