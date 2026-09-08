package cdk_preflight

import rego.v1

_pf_agvisc_missing(name) if {
	props := input.resources[name].properties
	is_object(props)
	object.get(props, "CredentialsArn", "__pf_absent") == "__pf_absent"
}

violation contains make_diag_full("pf-apigwv2-integration-subtype-credentials", "ERROR", name,
	"Properties.CredentialsArn",
	sprintf("IntegrationSubtype %s is set but CredentialsArn is not; the integration create fails with \"Role ARN must be specified for AWS integration configuration with Subtype: %s\"", [sub, sub]),
	"Set CredentialsArn to a role API Gateway can assume to call the service",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-apigatewayv2-integration.html") if {
	some name in resources_of_type("AWS::ApiGatewayV2::Integration")
	sub := resolve(name, "Properties.IntegrationSubtype")
	is_string(sub)
	_pf_agvisc_missing(name)
}
