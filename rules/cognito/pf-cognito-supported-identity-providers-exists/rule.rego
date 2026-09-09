package cdk_preflight

import rego.v1

# Judged only when the pool is a sibling resource: an imported pool can carry
# providers this template cannot see.

_pf_cgsipe_declared(pool, v) if {
	some idp in resources_of_type("AWS::Cognito::UserPoolIdentityProvider")
	resolve(idp, "Properties.UserPoolId") == pool
	resolve(idp, "Properties.ProviderName") == v
}

violation contains make_diag_full("pf-cognito-supported-identity-providers-exists", "ERROR", name,
	sprintf("Properties.SupportedIdentityProviders.%d", [p.index]),
	sprintf("identity provider '%s' is not defined for this pool; the client create fails with \"The provider %s does not exist for User Pool\"", [v, v]),
	"Add an AWS::Cognito::UserPoolIdentityProvider with that ProviderName, or drop it from SupportedIdentityProviders",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpoolclient.html") if {
	some name in resources_of_type("AWS::Cognito::UserPoolClient")
	pool := resolve(name, "Properties.UserPoolId")
	pool in resources_of_type("AWS::Cognito::UserPool")
	some p in flatten_list(name, "Properties.SupportedIdentityProviders")
	v := p.value
	is_string(v)
	v != "COGNITO"
	not _pf_cgsipe_declared(pool, v)
}
