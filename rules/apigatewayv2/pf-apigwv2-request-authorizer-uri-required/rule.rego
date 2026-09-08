package cdk_preflight

import rego.v1

_pf_agvraur_missing(name) if {
	props := input.resources[name].properties
	is_object(props)
	object.get(props, "AuthorizerUri", "__pf_absent") == "__pf_absent"
}

violation contains make_diag_full("pf-apigwv2-request-authorizer-uri-required", "ERROR", name,
	"Properties.AuthorizerUri",
	"AuthorizerType is REQUEST but AuthorizerUri is not set; the authorizer create fails with \"AuthorizerUri is a required field in an Authorizer\"",
	"Set AuthorizerUri to the Lambda invocation ARN of the authorizer function",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-apigatewayv2-authorizer.html") if {
	some name in resources_of_type("AWS::ApiGatewayV2::Authorizer")
	resolve(name, "Properties.AuthorizerType") == "REQUEST"
	_pf_agvraur_missing(name)
}
