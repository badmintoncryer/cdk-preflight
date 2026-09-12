package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-appsync-api-env-var-count-max", "ERROR", name,
	"Properties.EnvironmentVariables",
	sprintf("%d environment variables are set; the API create fails because an API is limited to 50", [count(ev)]),
	"Keep 50 or fewer environment variables",
	"https://docs.aws.amazon.com/appsync/latest/APIReference/API_PutGraphqlApiEnvironmentVariables.html") if {
	some name in resources_of_type("AWS::AppSync::GraphQLApi")
	ev := resolve(name, "Properties.EnvironmentVariables")
	is_object(ev)
	count(ev) > 50
}
