package cdk_preflight

import rego.v1

# The HTTP API side of this is pf-apigwv2-aws-proxy-payload-version; WebSocket
# APIs reject 2.0 outright.
violation contains make_diag_full("pf-apigwv2-websocket-payload-version", "ERROR", name,
	"Properties.PayloadFormatVersion",
	"An AWS_PROXY integration on a WebSocket API sets PayloadFormatVersion 2.0; the integration create fails with \"Unsupported PayloadFormatVersion: 2.0\"",
	"Drop PayloadFormatVersion (WebSocket AWS_PROXY integrations are 1.0 only)",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-apigatewayv2-integration.html") if {
	some name in resources_of_type("AWS::ApiGatewayV2::Integration")
	_pf_apigwv2lib_protocol(name) == "WEBSOCKET"
	resolve(name, "Properties.IntegrationType") == "AWS_PROXY"
	resolve(name, "Properties.PayloadFormatVersion") == "2.0"
}
