package cdk_preflight

import rego.v1

# Both spellings deploy-verified as accepted: the documented
# "$request.method $request.path" and the "${request.method} ${request.path}"
# form the service error itself prints (bench v02b).
_pf_agv2hrs_allowed := {"$request.method $request.path", "${request.method} ${request.path}"}

violation contains make_diag_full("pf-apigwv2-http-route-selection", "ERROR", name,
	"Properties.RouteSelectionExpression",
	sprintf("HTTP API RouteSelectionExpression '%s' is not supported; the API create fails with 'Route selection expression is currently limited to \"${request.method} ${request.path}\"'", [rse]),
	"Use $request.method $request.path, or omit the property (HTTP APIs default to it)",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-apigatewayv2-api.html") if {
	some name in resources_of_type("AWS::ApiGatewayV2::Api")
	resolve(name, "Properties.ProtocolType") == "HTTP"
	rse := resolve(name, "Properties.RouteSelectionExpression")
	is_string(rse)
	not rse in _pf_agv2hrs_allowed
}
