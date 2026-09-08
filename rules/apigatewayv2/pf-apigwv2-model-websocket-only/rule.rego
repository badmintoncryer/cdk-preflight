package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-apigwv2-model-websocket-only", "ERROR", name,
	"Properties.ApiId",
	"Model belongs to an HTTP API; the create fails with \"Currently, Models are not permitted for APIs with a protocol type of HTTP\"",
	"Drop the Model (request models exist for WebSocket APIs only)",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-apigatewayv2-model.html") if {
	some name in resources_of_type("AWS::ApiGatewayV2::Model")
	_pf_apigwv2lib_protocol(name) == "HTTP"
}
