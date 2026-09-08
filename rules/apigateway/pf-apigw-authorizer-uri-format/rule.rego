package cdk_preflight

import rego.v1

# Same wrapper-ARN shape as an AWS integration: the Lambda ARN alone is
# rejected.
violation contains make_diag_full("pf-apigw-authorizer-uri-format", "ERROR", name,
	"Properties.AuthorizerUri",
	sprintf("AuthorizerUri '%s' is not an API Gateway invocation ARN; the authorizer create fails with \"Invalid Authorizer URI ... Authorizer URI should be a valid API Gateway ARN\"", [uri]),
	"Use arn:<partition>:apigateway:<region>:lambda:path/2015-03-31/functions/<function arn>/invocations",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-apigateway-authorizer.html") if {
	some name in resources_of_type("AWS::ApiGateway::Authorizer")
	uri := resolve(name, "Properties.AuthorizerUri")
	is_string(uri)
	startswith(uri, "arn:")
	not regex.match(`^arn:[^:]*:apigateway:[^:]*:lambda:path/`, uri)
}
