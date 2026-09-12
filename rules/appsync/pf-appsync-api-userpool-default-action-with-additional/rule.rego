package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-appsync-api-userpool-default-action-with-additional", "ERROR", name,
	"Properties.UserPoolConfig.DefaultAction",
	"UserPoolConfig.DefaultAction is DENY while AdditionalAuthenticationProviders is set; the API create fails because the default action has to be ALLOW once more than one authentication mode is configured",
	"Set UserPoolConfig.DefaultAction: ALLOW, or drop AdditionalAuthenticationProviders",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appsync-graphqlapi-userpoolconfig.html") if {
	some name in resources_of_type("AWS::AppSync::GraphQLApi")
	resolve(name, "Properties.UserPoolConfig.DefaultAction") == "DENY"
	count(flatten_list(name, "Properties.AdditionalAuthenticationProviders")) > 0
}
