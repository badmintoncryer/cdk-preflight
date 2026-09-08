package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-apigwv2-route-response-websocket-only", "ERROR", name,
	"Properties.RouteId",
	"RouteResponse belongs to an HTTP API; the create fails with \"RouteResponses are currently not supported for this API protocol type.\"",
	"Drop the RouteResponse (it exists for WebSocket APIs only)",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-apigatewayv2-routeresponse.html") if {
	some name in resources_of_type("AWS::ApiGatewayV2::RouteResponse")
	_pf_apigwv2lib_protocol(name) == "HTTP"
}
