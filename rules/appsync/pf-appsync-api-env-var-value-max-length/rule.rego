package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-appsync-api-env-var-value-max-length", "ERROR", name,
	"Properties.EnvironmentVariables",
	sprintf("environment variable '%s' has a %d character value; the API create fails because a value is limited to 512 characters", [k, count(v)]),
	"Shorten the value to 512 characters or fewer",
	"https://docs.aws.amazon.com/appsync/latest/APIReference/API_PutGraphqlApiEnvironmentVariables.html") if {
	some name in resources_of_type("AWS::AppSync::GraphQLApi")
	ev := resolve(name, "Properties.EnvironmentVariables")
	is_object(ev)
	some k, v in ev
	is_string(v)
	count(v) > 512
}
