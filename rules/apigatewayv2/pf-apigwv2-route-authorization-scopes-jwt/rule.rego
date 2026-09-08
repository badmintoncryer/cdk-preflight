package cdk_preflight

import rego.v1

_pf_agvrasj_jwt(name) if resolve(name, "Properties.AuthorizationType") == "JWT"

violation contains make_diag_full("pf-apigwv2-route-authorization-scopes-jwt", "ERROR", name,
	"Properties.AuthorizationScopes",
	"AuthorizationScopes is set on a route whose AuthorizationType is not JWT; the route create fails with \"Authorization Scopes are only valid for COGNITO_USER_POOLS and JWT authorization type\"",
	"Set AuthorizationType: JWT, or drop AuthorizationScopes",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-apigatewayv2-route.html") if {
	some name in resources_of_type("AWS::ApiGatewayV2::Route")
	count(flatten_list(name, "Properties.AuthorizationScopes")) > 0
	not _pf_agvrasj_jwt(name)
}
