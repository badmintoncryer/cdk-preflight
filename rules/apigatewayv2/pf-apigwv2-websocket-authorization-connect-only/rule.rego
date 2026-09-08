package cdk_preflight

import rego.v1

# CUSTOM is the measured case; the service message is about authorization in
# general, so IAM and JWT are judged the same way.
violation contains make_diag_full("pf-apigwv2-websocket-authorization-connect-only", "ERROR", name,
	"Properties.AuthorizationType",
	sprintf("Route '%s' of a WebSocket API sets AuthorizationType %s; the route create fails with \"Currently, authorization is restricted to the $connect route only\"", [rk, at]),
	"Authorize the $connect route instead, and leave the other routes on AuthorizationType NONE",
	"https://docs.aws.amazon.com/apigateway/latest/developerguide/websocket-api-control-access.html") if {
	some name in resources_of_type("AWS::ApiGatewayV2::Route")
	_pf_apigwv2lib_protocol(name) == "WEBSOCKET"
	rk := resolve(name, "Properties.RouteKey")
	rk != "$connect"
	at := resolve(name, "Properties.AuthorizationType")
	at in {"CUSTOM", "AWS_IAM", "JWT"}
}
