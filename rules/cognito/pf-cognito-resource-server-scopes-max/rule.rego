package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cognito-resource-server-scopes-max", "ERROR", name,
	"Properties.Scopes",
	sprintf("the resource server has %d scopes; the create fails with \"Member must have length less than or equal to 100\"", [count(ss)]),
	"Keep the scope list at 100 entries or fewer",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpoolresourceserver.html") if {
	some name in resources_of_type("AWS::Cognito::UserPoolResourceServer")
	ss := flatten_list(name, "Properties.Scopes")
	count(ss) > 100
}
