package cdk_preflight

import rego.v1

_pf_ladvl_fix := "Use a published version number in AdditionalVersionWeights"

_pf_ladvl_url := "https://docs.aws.amazon.com/lambda/latest/api/API_AliasRoutingConfiguration.html"

violation contains make_diag_full("pf-lambda-alias-additional-version-not-latest", "ERROR", name,
	"Properties.RoutingConfig.AdditionalVersionWeights",
	"a routing entry that names $LATEST; a weighted alias can only split traffic between published versions",
	_pf_ladvl_fix, _pf_ladvl_url) if {
	some name in _pf_lam_alias
	props := _pf_lam_props(name)
	rc := _pf_lam_obj(props, "RoutingConfig")
	ws := _pf_lam_list(object.get(rc, "AdditionalVersionWeights", []))
	some w in ws
	is_object(w)
	object.get(w, "FunctionVersion", "") == "$LATEST"
}
