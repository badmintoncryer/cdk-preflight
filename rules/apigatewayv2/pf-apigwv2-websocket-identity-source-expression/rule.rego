package cdk_preflight

import rego.v1

# Same property, different DSL: WebSocket authorizers use route.request.*.
_pf_agvwise_ok(s) if regex.match(`^route\.request\.(header|querystring)\.[^ ]+$`, s)

violation contains make_diag_full("pf-apigwv2-websocket-identity-source-expression", "ERROR", name,
	"Properties.IdentitySource",
	sprintf("IdentitySource '%s' is not a WebSocket identity expression; the authorizer create fails with \"Invalid request identity source expression: %s\"", [s, s]),
	"Use route.request.header.<name> or route.request.querystring.<name> on WebSocket APIs",
	"https://docs.aws.amazon.com/apigateway/latest/developerguide/websocket-api-lambda-auth.html") if {
	some name in resources_of_type("AWS::ApiGatewayV2::Authorizer")
	_pf_apigwv2lib_protocol(name) == "WEBSOCKET"
	some item in flatten_list(name, "Properties.IdentitySource")
	s := item.value
	is_string(s)
	not _pf_agvwise_ok(s)
}
