package cdk_preflight

import rego.v1

_pf_apilambdaauthrequiresconfig_absent(n, k) if {
	props := input.resources[n].properties
	is_object(props)
	object.get(props, k, "__pf_absent") == "__pf_absent"
}

violation contains make_diag_full("pf-appsync-api-lambda-auth-requires-config", "ERROR", name,
	"Properties.LambdaAuthorizerConfig",
	"AuthenticationType is AWS_LAMBDA but LambdaAuthorizerConfig is not set; the API create fails because AppSync has no Lambda authorizer to validate tokens against",
	"Set Properties.LambdaAuthorizerConfig, or pick a different AuthenticationType",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appsync-graphqlapi.html") if {
	some name in resources_of_type("AWS::AppSync::GraphQLApi")
	resolve(name, "Properties.AuthenticationType") == "AWS_LAMBDA"
	_pf_apilambdaauthrequiresconfig_absent(name, "LambdaAuthorizerConfig")
}
