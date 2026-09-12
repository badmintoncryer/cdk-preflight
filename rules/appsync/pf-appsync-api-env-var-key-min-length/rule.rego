package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-appsync-api-env-var-key-min-length", "ERROR", name,
	"Properties.EnvironmentVariables",
	sprintf("environment variable key '%s' is %d character(s); the API create fails because a key must be 2-64 characters", [k, count(k)]),
	"Use an environment variable key of 2 to 64 characters",
	"https://docs.aws.amazon.com/appsync/latest/APIReference/API_PutGraphqlApiEnvironmentVariables.html") if {
	some name in resources_of_type("AWS::AppSync::GraphQLApi")
	ev := resolve(name, "Properties.EnvironmentVariables")
	is_object(ev)
	some k, _ in ev
	count(k) < 2
}
