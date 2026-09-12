package cdk_preflight

import rego.v1

# The engine knows this allowed-value list but reports it as W3030 (WARN),
# which never blocks a deploy; see AGENTS.md on the gray zone.
violation contains make_diag_full("pf-appsync-api-introspection-config-value", "ERROR", name,
	"Properties.IntrospectionConfig",
	sprintf("IntrospectionConfig '%s' is not one of ENABLED, DISABLED; the API create rejects the value", [v]),
	"Use one of ENABLED, DISABLED",
	"https://docs.aws.amazon.com/appsync/latest/APIReference/API_CreateGraphqlApi.html") if {
	some name in resources_of_type("AWS::AppSync::GraphQLApi")
	v := resolve(name, "Properties.IntrospectionConfig")
	is_string(v)
	not v in {"ENABLED", "DISABLED"}
}
