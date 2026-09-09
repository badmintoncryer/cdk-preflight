package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cognito-idp-social-required-keys", "ERROR", name,
	sprintf("Properties.ProviderDetails.%s", [k]),
	sprintf("%v ProviderDetails has no %s; the provider create fails with \"clientId, clientSecret and authorizeScopes are all required idp details.\"", [t, k]),
	"Set client_id, client_secret and authorize_scopes in ProviderDetails",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpoolidentityprovider.html") if {
	some name in resources_of_type("AWS::Cognito::UserPoolIdentityProvider")
	t := resolve(name, "Properties.ProviderType")
	t in {"Google", "Facebook", "LoginWithAmazon"}
	some k in ["client_id", "client_secret", "authorize_scopes"]
	_pf_coglib_absent(_pf_coglib_g2(name, "ProviderDetails", k))
}
