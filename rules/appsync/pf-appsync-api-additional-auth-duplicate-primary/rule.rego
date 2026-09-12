package cdk_preflight

import rego.v1

# API_KEY and AWS_LAMBDA have their own rules; excluded here so one
# template never trips two.
_pf_apiadditionalauthduplicateprimary_types(n) := array.concat(
	[object.get(input.resources[n].properties, "AuthenticationType", "")],
	[p.value.AuthenticationType | some p in flatten_list(n, "Properties.AdditionalAuthenticationProviders")],
)

violation contains make_diag_full("pf-appsync-api-additional-auth-duplicate-primary", "ERROR", name,
	"Properties.AdditionalAuthenticationProviders",
	sprintf("authentication mode '%s' appears more than once across AuthenticationType and AdditionalAuthenticationProviders; the API create rejects duplicate authentication providers", [t]),
	"List each authentication mode once",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appsync-graphqlapi-additionalauthenticationprovider.html") if {
	some name in resources_of_type("AWS::AppSync::GraphQLApi")
	types := _pf_apiadditionalauthduplicateprimary_types(name)
	some i, t in types
	not t in {"API_KEY", "AWS_LAMBDA", ""}
	some j, u in types
	j > i
	u == t
}
