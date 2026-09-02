package cdk_preflight

import rego.v1

# WebSocket route keys are free-form, so this only judges routes whose Api
# sibling is provably HTTP. TRACE is deploy-verified as rejected; paths with
# spaces are left alone (unmeasured).
_pf_agv2rk_methods := {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "ANY"}

_pf_agv2rk_http_api(name) if {
	api := resolve(name, "Properties.ApiId")
	api in resources_of_type("AWS::ApiGatewayV2::Api")
	resolve(api, "Properties.ProtocolType") == "HTTP"
}

_pf_agv2rk_ok(rk) if rk == "$default"

_pf_agv2rk_ok(rk) if {
	parts := split(rk, " ")
	count(parts) >= 2
	parts[0] in _pf_agv2rk_methods
	startswith(parts[1], "/")
}

violation contains make_diag_full("pf-apigwv2-http-route-key", "ERROR", name,
	"Properties.RouteKey",
	sprintf("RouteKey '%s' is malformed for an HTTP API; the route create fails with 'The provided route key is not formatted properly for HTTP protocol. Format should be \"[HTTP METHOD] /[RESOURCE PATH]\" or \"$default\"'", [rk]),
	"Use \"METHOD /path\" with METHOD one of GET POST PUT PATCH DELETE HEAD OPTIONS ANY, or $default",
	"https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-develop-routes.html") if {
	some name in resources_of_type("AWS::ApiGatewayV2::Route")
	_pf_agv2rk_http_api(name)
	rk := resolve(name, "Properties.RouteKey")
	is_string(rk)
	not _pf_agv2rk_ok(rk)
}
