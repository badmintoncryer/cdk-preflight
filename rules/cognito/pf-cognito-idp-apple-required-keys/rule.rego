package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cognito-idp-apple-required-keys", "ERROR", name,
	sprintf("Properties.ProviderDetails.%s", [k]),
	sprintf("SignInWithApple ProviderDetails has no %s; the provider create fails with \"clientId, privateKey, teamId, and keyId are all required idp details.\"", [k]),
	"Set client_id, team_id, key_id, private_key and authorize_scopes in ProviderDetails",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpoolidentityprovider.html") if {
	some name in resources_of_type("AWS::Cognito::UserPoolIdentityProvider")
	resolve(name, "Properties.ProviderType") == "SignInWithApple"
	some k in ["client_id", "team_id", "key_id", "private_key", "authorize_scopes"]
	_pf_coglib_absent(_pf_coglib_g2(name, "ProviderDetails", k))
}
