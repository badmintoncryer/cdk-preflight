package cdk_preflight

import rego.v1

_pf_apicognitorequiresuserpoolconfig_absent(n, k) if {
	props := input.resources[n].properties
	is_object(props)
	object.get(props, k, "__pf_absent") == "__pf_absent"
}

violation contains make_diag_full("pf-appsync-api-cognito-requires-userpool-config", "ERROR", name,
	"Properties.UserPoolConfig",
	"AuthenticationType is AMAZON_COGNITO_USER_POOLS but UserPoolConfig is not set; the API create fails because AppSync has no Cognito user pool to validate tokens against",
	"Set Properties.UserPoolConfig, or pick a different AuthenticationType",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appsync-graphqlapi.html") if {
	some name in resources_of_type("AWS::AppSync::GraphQLApi")
	resolve(name, "Properties.AuthenticationType") == "AMAZON_COGNITO_USER_POOLS"
	_pf_apicognitorequiresuserpoolconfig_absent(name, "UserPoolConfig")
}
