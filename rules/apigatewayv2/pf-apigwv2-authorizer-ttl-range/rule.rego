package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-apigwv2-authorizer-ttl-range", "ERROR", name,
	"Properties.AuthorizerResultTtlInSeconds",
	sprintf("AuthorizerResultTtlInSeconds %v is over the cap; the authorizer create fails with \"Authorizer result TTL outside allowable range. TTL must be between 0 and 3600 seconds.\"", [ttl]),
	"Use a TTL between 0 and 3600 seconds",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-apigatewayv2-authorizer.html") if {
	some name in resources_of_type("AWS::ApiGatewayV2::Authorizer")
	ttl := to_number(resolve(name, "Properties.AuthorizerResultTtlInSeconds"))
	ttl > 3600
}
