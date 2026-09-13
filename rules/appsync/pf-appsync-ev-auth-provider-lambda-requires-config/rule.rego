package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-appsync-ev-auth-provider-lambda-requires-config", "ERROR", name,
	"Properties.EventConfig.AuthProviders",
	"an EventConfig.AuthProviders entry is AWS_LAMBDA but carries no LambdaAuthorizerConfig; the API create fails because AppSync has nothing to validate tokens against",
	"Set LambdaAuthorizerConfig on that auth provider, or use a different AuthType",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-appsync-api.html") if {
	some name in resources_of_type("AWS::AppSync::Api")
	some p in flatten_list(name, "Properties.EventConfig.AuthProviders")
	p.value.AuthType == "AWS_LAMBDA"
	object.get(p.value, "LambdaAuthorizerConfig", "__pf_absent") == "__pf_absent"
}
