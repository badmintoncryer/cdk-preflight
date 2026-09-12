package cdk_preflight

import rego.v1

# Judged only when the API is a sibling resource: an ApiId that is a literal
# or a parameter points at an API this template cannot see.
_pf_apikeyrequiresapikeyauth_types(n) := array.concat(
	[object.get(input.resources[n].properties, "AuthenticationType", "")],
	[p.value.AuthenticationType | some p in flatten_list(n, "Properties.AdditionalAuthenticationProviders")],
)

violation contains make_diag_full("pf-appsync-api-key-requires-api-key-auth", "ERROR", name,
	"Properties.ApiId",
	sprintf("API '%s' in this template does not accept API_KEY authentication; the API key create fails because the API has no API_KEY authentication mode", [api]),
	"Set AuthenticationType: API_KEY on the API, or drop the AWS::AppSync::ApiKey",
	"https://docs.aws.amazon.com/appsync/latest/devguide/security-authz.html") if {
	some name in resources_of_type("AWS::AppSync::ApiKey")
	api := resolve(name, "Properties.ApiId")
	api in resources_of_type("AWS::AppSync::GraphQLApi")
	not "API_KEY" in _pf_apikeyrequiresapikeyauth_types(api)
}
