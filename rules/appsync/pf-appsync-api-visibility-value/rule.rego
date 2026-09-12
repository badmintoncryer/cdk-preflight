package cdk_preflight

import rego.v1

# The engine knows this allowed-value list but reports it as W3030 (WARN),
# which never blocks a deploy; see AGENTS.md on the gray zone.
violation contains make_diag_full("pf-appsync-api-visibility-value", "ERROR", name,
	"Properties.Visibility",
	sprintf("Visibility '%s' is not one of GLOBAL, PRIVATE; the API create rejects the value", [v]),
	"Use one of GLOBAL, PRIVATE",
	"https://docs.aws.amazon.com/appsync/latest/APIReference/API_CreateGraphqlApi.html") if {
	some name in resources_of_type("AWS::AppSync::GraphQLApi")
	v := resolve(name, "Properties.Visibility")
	is_string(v)
	not v in {"GLOBAL", "PRIVATE"}
}
