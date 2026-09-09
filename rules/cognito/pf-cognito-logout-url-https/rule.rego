package cdk_preflight

import rego.v1

_pf_cgluh_local(v) if regex.match(`^http://(localhost|127\.0\.0\.1|\[::1\])(:[0-9]+)?(/|$)`, v)

violation contains make_diag_full("pf-cognito-logout-url-https", "ERROR", name,
	sprintf("Properties.LogoutURLs.%d", [u.index]),
	sprintf("logout URL '%s' uses plain http; the client create fails with \"%s cannot use the HTTP protocol.\"", [v, v]),
	"Use https:// for the logout URL (plain http is only allowed for localhost)",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpoolclient.html") if {
	some name in resources_of_type("AWS::Cognito::UserPoolClient")
	some u in flatten_list(name, "Properties.LogoutURLs")
	v := u.value
	is_string(v)
	startswith(v, "http://")
	not _pf_cgluh_local(v)
}
