package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-apigwv2-integration-subtype-payload-version", "ERROR", name,
	"Properties.PayloadFormatVersion",
	sprintf("IntegrationSubtype %s is used with PayloadFormatVersion %s; AWS service integrations are 1.0 only and the integration create fails with \"Operation: %s is not supported.\"", [sub, v, sub]),
	"Set PayloadFormatVersion: \"1.0\" for an AWS service (subtype) integration",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-apigatewayv2-integration.html") if {
	some name in resources_of_type("AWS::ApiGatewayV2::Integration")
	sub := resolve(name, "Properties.IntegrationSubtype")
	is_string(sub)
	v := resolve(name, "Properties.PayloadFormatVersion")
	is_string(v)
	v != "1.0"
}
