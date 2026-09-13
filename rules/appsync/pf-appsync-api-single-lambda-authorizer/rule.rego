package cdk_preflight

import rego.v1

_pf_apisinglelambdaauthorizer_types(n) := array.concat(
	[object.get(input.resources[n].properties, "AuthenticationType", "")],
	[p.value.AuthenticationType | some p in flatten_list(n, "Properties.AdditionalAuthenticationProviders")],
)

violation contains make_diag_full("pf-appsync-api-single-lambda-authorizer", "ERROR", name,
	"Properties.AdditionalAuthenticationProviders",
	sprintf("AWS_LAMBDA appears %d times across AuthenticationType and AdditionalAuthenticationProviders; the API create fails because an API can have at most one Lambda authorizer", [count(lambdas)]),
	"Keep a single AWS_LAMBDA authentication provider",
	"https://docs.aws.amazon.com/appsync/latest/devguide/security-authz.html") if {
	some name in resources_of_type("AWS::AppSync::GraphQLApi")
	lambdas := [t | some t in _pf_apisinglelambdaauthorizer_types(name); t == "AWS_LAMBDA"]
	count(lambdas) > 1
}
