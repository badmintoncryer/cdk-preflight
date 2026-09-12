package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-appsync-api-userpool-config-requires-cognito-auth", "ERROR", name,
	"Properties.UserPoolConfig",
	"UserPoolConfig is set but AuthenticationType is not AMAZON_COGNITO_USER_POOLS; the API create rejects the unused user pool configuration",
	"Set AuthenticationType: AMAZON_COGNITO_USER_POOLS, move the pool into AdditionalAuthenticationProviders, or drop UserPoolConfig",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appsync-graphqlapi.html") if {
	some name in resources_of_type("AWS::AppSync::GraphQLApi")
	is_object(resolve(name, "Properties.UserPoolConfig"))
	resolve(name, "Properties.AuthenticationType") != "AMAZON_COGNITO_USER_POOLS"
}
