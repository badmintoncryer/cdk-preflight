package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-apigwv2-http-route-no-api-key", "ERROR", name,
	"Properties.ApiKeyRequired",
	"ApiKeyRequired is set on a route of an HTTP API; the route create fails with \"ApiKeyRequired is not currently supported for HTTP APIs.\"",
	"Drop ApiKeyRequired (API keys exist for WebSocket APIs and REST APIs only)",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-apigatewayv2-route.html") if {
	some name in resources_of_type("AWS::ApiGatewayV2::Route")
	_pf_apigwv2lib_protocol(name) == "HTTP"
	resolve(name, "Properties.ApiKeyRequired") == true
}
