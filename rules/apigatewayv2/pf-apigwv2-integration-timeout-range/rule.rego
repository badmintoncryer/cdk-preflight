package cdk_preflight

import rego.v1

_pf_agvitr_bad(t) if t < 50

_pf_agvitr_bad(t) if t > 30000

violation contains make_diag_full("pf-apigwv2-integration-timeout-range", "ERROR", name,
	"Properties.TimeoutInMillis",
	sprintf("TimeoutInMillis %v is outside 50-30000 for an HTTP API; the integration create fails with \"Timeout should be between 50 ms and 30000 ms\"", [t]),
	"Use an integration timeout between 50 and 30000 milliseconds",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-apigatewayv2-integration.html") if {
	some name in resources_of_type("AWS::ApiGatewayV2::Integration")
	_pf_apigwv2lib_protocol(name) == "HTTP"
	t := to_number(resolve(name, "Properties.TimeoutInMillis"))
	_pf_agvitr_bad(t)
}
