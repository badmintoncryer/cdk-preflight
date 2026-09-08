package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-apigwv2-jwt-audience-required", "ERROR", name,
	"Properties.JwtConfiguration.Audience",
	"A JWT authorizer has no JwtConfiguration.Audience; the authorizer create is rejected without at least one audience",
	"List the audiences (client ids) the tokens are issued for",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-apigatewayv2-authorizer-jwtconfiguration.html") if {
	some name in resources_of_type("AWS::ApiGatewayV2::Authorizer")
	resolve(name, "Properties.AuthorizerType") == "JWT"
	count(flatten_list(name, "Properties.JwtConfiguration.Audience")) == 0
}
