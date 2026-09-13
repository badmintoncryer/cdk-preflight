package cdk_preflight

import rego.v1

_pf_apimergedrequiresexecutionrole_absent(n, k) if {
	props := input.resources[n].properties
	is_object(props)
	object.get(props, k, "__pf_absent") == "__pf_absent"
}

violation contains make_diag_full("pf-appsync-api-merged-requires-execution-role", "ERROR", name,
	"Properties.MergedApiExecutionRoleArn",
	"ApiType is MERGED but MergedApiExecutionRoleArn is not set; the API create fails because a merged API needs a role to read its source APIs",
	"Set MergedApiExecutionRoleArn to a role AppSync can assume",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appsync-graphqlapi.html") if {
	some name in resources_of_type("AWS::AppSync::GraphQLApi")
	resolve(name, "Properties.ApiType") == "MERGED"
	_pf_apimergedrequiresexecutionrole_absent(name, "MergedApiExecutionRoleArn")
}
