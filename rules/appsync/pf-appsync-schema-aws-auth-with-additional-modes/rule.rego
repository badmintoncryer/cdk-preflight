package cdk_preflight

import rego.v1

# Judged only when the API is a sibling resource, so its authentication modes
# are visible in this template.
violation contains make_diag_full("pf-appsync-schema-aws-auth-with-additional-modes", "ERROR", name,
	"Properties.Definition",
	sprintf("the SDL uses @aws_auth while API '%s' configures AdditionalAuthenticationProviders; the schema create fails because @aws_auth cannot be combined with additional authentication modes", [api]),
	"Use @aws_cognito_user_pools instead of @aws_auth when the API has more than one authentication mode",
	"https://docs.aws.amazon.com/appsync/latest/devguide/security-authz.html") if {
	some name in resources_of_type("AWS::AppSync::GraphQLSchema")
	sdl := resolve(name, "Properties.Definition")
	is_string(sdl)
	contains(sdl, "@aws_auth")
	api := resolve(name, "Properties.ApiId")
	api in resources_of_type("AWS::AppSync::GraphQLApi")
	count(flatten_list(api, "Properties.AdditionalAuthenticationProviders")) > 0
}
