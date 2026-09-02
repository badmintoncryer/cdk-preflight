package cdk_preflight

import rego.v1

# A JWT authorizer is nothing but its issuer/audience config, so the
# create call rejects its absence. Absence is proven against the
# preprocessed document (see AGENTS.md).
_pf_agv2jac_missing(name) if {
	props := input.resources[name].properties
	is_object(props)
	object.get(props, "JwtConfiguration", "__pf_absent") == "__pf_absent"
}

violation contains make_diag_full("pf-apigwv2-jwt-authorizer-config", "ERROR", name,
	"Properties.JwtConfiguration",
	"JWT authorizer has no JwtConfiguration; the authorizer create fails with \"JwtConfiguration must not be null for JWT Authorizer\"",
	"Set JwtConfiguration with Issuer and Audience",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-apigatewayv2-authorizer.html") if {
	some name in resources_of_type("AWS::ApiGatewayV2::Authorizer")
	resolve(name, "Properties.AuthorizerType") == "JWT"
	_pf_agv2jac_missing(name)
}
