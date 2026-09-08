package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-apigwv2-authorizer-ttl-identity-source", "ERROR", name,
	"Properties.IdentitySource",
	sprintf("AuthorizerResultTtlInSeconds is %v (caching on) but IdentitySource is empty; the authorizer create fails with \"Identity source must be set if authorizer caching is enabled (TTL is greater than 0)\"", [ttl]),
	"List the identity sources the cache key is built from, or set AuthorizerResultTtlInSeconds: 0",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-apigatewayv2-authorizer.html") if {
	some name in resources_of_type("AWS::ApiGatewayV2::Authorizer")
	ttl := to_number(resolve(name, "Properties.AuthorizerResultTtlInSeconds"))
	ttl > 0
	count(flatten_list(name, "Properties.IdentitySource")) == 0
}
