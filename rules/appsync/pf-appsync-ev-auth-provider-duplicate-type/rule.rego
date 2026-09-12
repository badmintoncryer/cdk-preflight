package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-appsync-ev-auth-provider-duplicate-type", "ERROR", name,
	"Properties.EventConfig.AuthProviders",
	sprintf("EventConfig.AuthProviders lists '%s' more than once; the API create rejects duplicate authentication providers", [p.value.AuthType]),
	"List each auth type once",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-appsync-api.html") if {
	some name in resources_of_type("AWS::AppSync::Api")
	ps := flatten_list(name, "Properties.EventConfig.AuthProviders")
	some i, p in ps
	some j, q in ps
	j > i
	q.value.AuthType == p.value.AuthType
}
