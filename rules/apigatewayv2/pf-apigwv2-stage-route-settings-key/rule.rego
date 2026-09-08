package cdk_preflight

import rego.v1

# Per-route settings are keyed by RouteKey, so the stage and the routes have to
# agree - two resources the template holds side by side.
_pf_agvsrsk_routes contains [api, rk] if {
	some r in resources_of_type("AWS::ApiGatewayV2::Route")
	api := resolve(r, "Properties.ApiId")
	rk := resolve(r, "Properties.RouteKey")
	is_string(rk)
}

_pf_agvsrsk_known(api, k) if [api, k] in _pf_agvsrsk_routes

# Skip when the routes live in another stack: without a route of this API in
# the template there is nothing to compare the keys against.
_pf_agvsrsk_has_routes(api) if {
	some entry in _pf_agvsrsk_routes
	entry[0] == api
}

violation contains make_diag_full("pf-apigwv2-stage-route-settings-key", "ERROR", name,
	"Properties.RouteSettings",
	sprintf("RouteSettings is keyed by '%s', which no Route of this API declares; the stage create fails with \"Unable to find Route by key %s within the provided RouteSettings\"", [k, k]),
	"Key RouteSettings by a RouteKey the template actually creates",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-apigatewayv2-stage.html") if {
	some name in resources_of_type("AWS::ApiGatewayV2::Stage")
	api := resolve(name, "Properties.ApiId")
	api in resources_of_type("AWS::ApiGatewayV2::Api")
	_pf_agvsrsk_has_routes(api)
	rs := resolve(name, "Properties.RouteSettings")
	is_object(rs)
	some k, _ in rs
	not _pf_agvsrsk_known(api, k)
}
