package cdk_preflight

import rego.v1

_pf_cgdrum_member(cbs, d) if {
	some c in cbs
	c.value == d
}

violation contains make_diag_full("pf-cognito-default-redirect-uri-member", "ERROR", name,
	"Properties.DefaultRedirectURI",
	sprintf("DefaultRedirectURI '%s' is not in CallbackURLs; the client create fails with \"The default redirect URI %s is not in the callback URIs list.\"", [d, d]),
	"Use one of the CallbackURLs as the DefaultRedirectURI",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpoolclient.html") if {
	some name in resources_of_type("AWS::Cognito::UserPoolClient")
	d := resolve(name, "Properties.DefaultRedirectURI")
	is_string(d)
	cbs := flatten_list(name, "Properties.CallbackURLs")
	count(cbs) > 0
	not _pf_cgdrum_member(cbs, d)
}
