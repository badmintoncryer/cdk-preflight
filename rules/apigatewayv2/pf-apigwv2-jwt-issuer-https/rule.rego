package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-apigwv2-jwt-issuer-https", "ERROR", name,
	"Properties.JwtConfiguration.Issuer",
	sprintf("JwtConfiguration.Issuer '%s' is not an https URL; the authorizer create fails with \"Invalid issuer: Issuer is not a valid URL for JWT Authorizer\"", [iss]),
	"Use the identity provider's https:// issuer URL",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-apigatewayv2-authorizer-jwtconfiguration.html") if {
	some name in resources_of_type("AWS::ApiGatewayV2::Authorizer")
	iss := resolve(name, "Properties.JwtConfiguration.Issuer")
	is_string(iss)
	not input.resources[iss]
	not startswith(iss, "https://")
}
