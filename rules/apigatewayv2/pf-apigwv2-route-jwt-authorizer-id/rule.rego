package cdk_preflight

import rego.v1

_pf_agvrjai_missing(name) if {
	props := input.resources[name].properties
	is_object(props)
	object.get(props, "AuthorizerId", "__pf_absent") == "__pf_absent"
}

violation contains make_diag_full("pf-apigwv2-route-jwt-authorizer-id", "ERROR", name,
	"Properties.AuthorizerId",
	"AuthorizationType is JWT but AuthorizerId is not set; the route create fails with \"Setting the authorization type to JWT requires a valid JWT authorizer.\"",
	"Set AuthorizerId to the JWT authorizer this route should use",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-apigatewayv2-route.html") if {
	some name in resources_of_type("AWS::ApiGatewayV2::Route")
	resolve(name, "Properties.AuthorizationType") == "JWT"
	_pf_agvrjai_missing(name)
}
