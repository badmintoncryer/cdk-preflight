package cdk_preflight

import rego.v1

# Judged only when the pool is a sibling resource: an imported pool can carry
# resource servers this template cannot see.

_pf_cgosu_custom(pool, v) if {
	some rs in resources_of_type("AWS::Cognito::UserPoolResourceServer")
	resolve(rs, "Properties.UserPoolId") == pool
	id := resolve(rs, "Properties.Identifier")
	is_string(id)
	startswith(v, concat("", [id, "/"]))
}

violation contains make_diag_full("pf-cognito-oauth-scopes-unknown", "ERROR", name,
	sprintf("Properties.AllowedOAuthScopes.%d", [s.index]),
	sprintf("OAuth scope '%s' is neither a standard scope nor a scope of a resource server on this pool; the client create fails with \"Invalid scope requested: %s\"", [v, v]),
	"Use a standard scope (openid, email, phone, profile, aws.cognito.signin.user.admin) or declare the resource server that owns it",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpoolclient.html") if {
	some name in resources_of_type("AWS::Cognito::UserPoolClient")
	pool := resolve(name, "Properties.UserPoolId")
	pool in resources_of_type("AWS::Cognito::UserPool")
	some s in flatten_list(name, "Properties.AllowedOAuthScopes")
	v := s.value
	is_string(v)
	not v in _pf_coglib_std_scopes
	not _pf_cgosu_custom(pool, v)
}
