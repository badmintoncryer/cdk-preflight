package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-apigwv2-integration-response-websocket-only", "ERROR", name,
	"Properties.IntegrationId",
	"IntegrationResponse belongs to an HTTP API; the create fails with \"IntegrationResponses are currently not supported for this API protocol type.\"",
	"Drop the IntegrationResponse (it exists for WebSocket APIs only)",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-apigatewayv2-integrationresponse.html") if {
	some name in resources_of_type("AWS::ApiGatewayV2::IntegrationResponse")
	_pf_apigwv2lib_protocol(name) == "HTTP"
}
