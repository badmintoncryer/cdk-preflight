package cdk_preflight

import rego.v1

# WebSocket APIs route by evaluating this expression against each message,
# so the create call rejects its absence. Absence is proven against the
# preprocessed document (see AGENTS.md).
_pf_agv2wrs_missing(name) if {
	props := input.resources[name].properties
	is_object(props)
	object.get(props, "RouteSelectionExpression", "__pf_absent") == "__pf_absent"
}

violation contains make_diag_full("pf-apigwv2-websocket-route-selection", "ERROR", name,
	"Properties.RouteSelectionExpression",
	"WebSocket API has no RouteSelectionExpression; the API create fails with \"Invalid routeSelectionExpression\"",
	"Set RouteSelectionExpression, e.g. $request.body.action",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-apigatewayv2-api.html") if {
	some name in resources_of_type("AWS::ApiGatewayV2::Api")
	resolve(name, "Properties.ProtocolType") == "WEBSOCKET"
	_pf_agv2wrs_missing(name)
}
