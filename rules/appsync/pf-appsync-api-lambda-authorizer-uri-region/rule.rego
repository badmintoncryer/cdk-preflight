package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-appsync-api-lambda-authorizer-uri-region", "ERROR", name,
	"Properties.LambdaAuthorizerConfig.AuthorizerUri",
	sprintf("the Lambda authorizer is in region '%s' but this stack deploys to '%s'; the API create fails because AppSync only invokes an authorizer in its own region", [parts[3], region]),
	"Use a Lambda function in the region this stack deploys to",
	"https://docs.aws.amazon.com/appsync/latest/devguide/security-authz.html") if {
	some name in resources_of_type("AWS::AppSync::GraphQLApi")
	region := data.cdk_preflight.deploy_region
	uri := resolve(name, "Properties.LambdaAuthorizerConfig.AuthorizerUri")
	is_string(uri)
	parts := split(uri, ":")
	count(parts) > 3
	parts[2] == "lambda"
	parts[3] != region
}
