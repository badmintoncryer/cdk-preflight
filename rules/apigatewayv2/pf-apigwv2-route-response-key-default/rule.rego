package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-apigwv2-route-response-key-default", "ERROR", name,
	"Properties.RouteResponseKey",
	sprintf("RouteResponseKey is '%s'; the route response create fails with \"Currently, only $default is supported as a RouteResponseKey.\"", [k]),
	"Use RouteResponseKey: $default",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-apigatewayv2-routeresponse.html") if {
	some name in resources_of_type("AWS::ApiGatewayV2::RouteResponse")
	k := resolve(name, "Properties.RouteResponseKey")
	is_string(k)
	not input.resources[k]
	k != "$default"
}
