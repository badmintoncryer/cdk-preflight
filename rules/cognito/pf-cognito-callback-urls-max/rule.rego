package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cognito-callback-urls-max", "ERROR", name,
	"Properties.CallbackURLs",
	sprintf("the client has %d callback URLs; the client create fails with \"Member must have length less than or equal to 100\"", [count(us)]),
	"Keep the callback URL list at 100 entries or fewer",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpoolclient.html") if {
	some name in resources_of_type("AWS::Cognito::UserPoolClient")
	us := flatten_list(name, "Properties.CallbackURLs")
	count(us) > 100
}
