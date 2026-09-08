package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-apigwv2-websocket-no-cors", "ERROR", name,
	"Properties.CorsConfiguration",
	"CorsConfiguration is set on a WEBSOCKET API; the API create fails with \"Cors is not supported for WEBSOCKET protocolType\"",
	"Drop CorsConfiguration, or make the API an HTTP API",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-apigatewayv2-api.html") if {
	some name in resources_of_type("AWS::ApiGatewayV2::Api")
	resolve(name, "Properties.ProtocolType") == "WEBSOCKET"
	is_object(resolve(name, "Properties.CorsConfiguration"))
}
