package cdk_preflight

import rego.v1

_pf_apgmasc_cognito(name) if resolve(name, "Properties.AuthorizationType") == "COGNITO_USER_POOLS"

violation contains make_diag_full("pf-apigw-method-authorization-scopes-cognito", "ERROR", name,
	"Properties.AuthorizationScopes",
	"AuthorizationScopes is set on a method whose AuthorizationType is not COGNITO_USER_POOLS; the method create fails with \"Authorization Scopes are only valid for COGNITO_USER_POOLS authorization type\"",
	"Set AuthorizationType: COGNITO_USER_POOLS, or drop AuthorizationScopes",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-apigateway-method.html") if {
	some name in resources_of_type("AWS::ApiGateway::Method")
	count(flatten_list(name, "Properties.AuthorizationScopes")) > 0
	not _pf_apgmasc_cognito(name)
}
