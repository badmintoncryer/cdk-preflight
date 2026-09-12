package cdk_preflight

import rego.v1

_pf_apiexecutionrolerequiresmerged_merged(n) if resolve(n, "Properties.ApiType") == "MERGED"

violation contains make_diag_full("pf-appsync-api-execution-role-requires-merged", "ERROR", name,
	"Properties.MergedApiExecutionRoleArn",
	"MergedApiExecutionRoleArn is set on an API whose ApiType is not MERGED; the API create rejects the unused role",
	"Set ApiType: MERGED, or drop MergedApiExecutionRoleArn",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appsync-graphqlapi.html") if {
	some name in resources_of_type("AWS::AppSync::GraphQLApi")
	is_string(resolve(name, "Properties.MergedApiExecutionRoleArn"))
	not _pf_apiexecutionrolerequiresmerged_merged(name)
}
