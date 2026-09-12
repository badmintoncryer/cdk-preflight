package cdk_preflight

import rego.v1

# The engine knows this allowed-value list but reports it as W3030 (WARN),
# which never blocks a deploy; see AGENTS.md on the gray zone.
violation contains make_diag_full("pf-appsync-api-type-value", "ERROR", name,
	"Properties.ApiType",
	sprintf("ApiType '%s' is not one of GRAPHQL, MERGED; the API create rejects the value", [v]),
	"Use one of GRAPHQL, MERGED",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appsync-graphqlapi.html") if {
	some name in resources_of_type("AWS::AppSync::GraphQLApi")
	v := resolve(name, "Properties.ApiType")
	is_string(v)
	not v in {"GRAPHQL", "MERGED"}
}
