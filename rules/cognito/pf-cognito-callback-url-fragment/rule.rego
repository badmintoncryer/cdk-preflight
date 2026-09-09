package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cognito-callback-url-fragment", "ERROR", name,
	sprintf("Properties.CallbackURLs.%d", [u.index]),
	sprintf("callback URL '%s' has a fragment; the client create fails with \"%s cannot use fragment\"", [v, v]),
	"Drop the #fragment from the callback URL",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpoolclient.html") if {
	some name in resources_of_type("AWS::Cognito::UserPoolClient")
	some u in flatten_list(name, "Properties.CallbackURLs")
	v := u.value
	is_string(v)
	contains(v, "#")
}
