package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-appsync-api-additional-auth-no-api-key", "ERROR", name,
	"Properties.AdditionalAuthenticationProviders",
	"API_KEY is listed in AdditionalAuthenticationProviders; the API create fails because API_KEY is only valid as the primary AuthenticationType",
	"Set AuthenticationType: API_KEY, and use a different mode for the additional provider",
	"https://docs.aws.amazon.com/appsync/latest/devguide/security-authz.html") if {
	some name in resources_of_type("AWS::AppSync::GraphQLApi")
	some p in flatten_list(name, "Properties.AdditionalAuthenticationProviders")
	p.value.AuthenticationType == "API_KEY"
}
