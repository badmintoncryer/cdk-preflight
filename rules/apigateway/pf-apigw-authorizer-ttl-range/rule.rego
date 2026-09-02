package cdk_preflight

import rego.v1

# The registry schema types the TTL as a bare integer; the 3600 ceiling is
# only in the service.
violation contains make_diag_full("pf-apigw-authorizer-ttl-range", "ERROR", name,
	"Properties.AuthorizerResultTtlInSeconds",
	sprintf("AuthorizerResultTtlInSeconds %v is over the cap; the authorizer create fails with \"Authorizer result TTL outside allowable range. TTL must be between 0 and 3600 seconds.\"", [ttl]),
	"Use a TTL between 0 and 3600 seconds",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-apigateway-authorizer.html") if {
	some name in resources_of_type("AWS::ApiGateway::Authorizer")
	ttl := to_number(resolve(name, "Properties.AuthorizerResultTtlInSeconds"))
	ttl > 3600
}
