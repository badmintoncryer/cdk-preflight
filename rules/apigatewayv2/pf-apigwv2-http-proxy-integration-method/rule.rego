package cdk_preflight

import rego.v1

_pf_agvhpim_missing(name) if {
	props := input.resources[name].properties
	is_object(props)
	object.get(props, "IntegrationMethod", "__pf_absent") == "__pf_absent"
}

violation contains make_diag_full("pf-apigwv2-http-proxy-integration-method", "ERROR", name,
	"Properties.IntegrationMethod",
	"IntegrationType is HTTP_PROXY but IntegrationMethod is not set; the integration create fails with \"HttpMethod parameter method must be specified for integrationType HTTPPROXY\"",
	"Set IntegrationMethod (e.g. ANY or GET)",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-apigatewayv2-integration.html") if {
	some name in resources_of_type("AWS::ApiGatewayV2::Integration")
	resolve(name, "Properties.IntegrationType") == "HTTP_PROXY"
	_pf_agvhpim_missing(name)
}
