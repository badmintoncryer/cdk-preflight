package cdk_preflight

import rego.v1

# Same property, lower ceiling: the limit is protocol-dependent.
_pf_agvwitr_bad(t) if t < 50

_pf_agvwitr_bad(t) if t > 29000

violation contains make_diag_full("pf-apigwv2-websocket-integration-timeout-range", "ERROR", name,
	"Properties.TimeoutInMillis",
	sprintf("TimeoutInMillis %v is outside 50-29000 for a WebSocket API; the integration create fails with \"Timeout should be between 50 ms and 29000 ms\"", [t]),
	"Use an integration timeout between 50 and 29000 milliseconds on WebSocket APIs",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-apigatewayv2-integration.html") if {
	some name in resources_of_type("AWS::ApiGatewayV2::Integration")
	_pf_apigwv2lib_protocol(name) == "WEBSOCKET"
	t := to_number(resolve(name, "Properties.TimeoutInMillis"))
	_pf_agvwitr_bad(t)
}
