package cdk_preflight

import rego.v1

_pf_ladrl_fix := "Publish a version and point the alias at it before adding RoutingConfig"

_pf_ladrl_url := "https://docs.aws.amazon.com/lambda/latest/dg/configuring-alias-routing.html"

violation contains make_diag_full("pf-lambda-alias-routing-not-latest", "ERROR", name,
	"Properties.FunctionVersion",
	"a weighted alias whose own FunctionVersion is $LATEST; routing splits traffic between published versions and $LATEST is not one",
	_pf_ladrl_fix, _pf_ladrl_url) if {
	some name in _pf_lam_alias
	props := _pf_lam_props(name)
	object.get(props, "FunctionVersion", "") == "$LATEST"
	_pf_lam_has_key(props, "RoutingConfig")
}
