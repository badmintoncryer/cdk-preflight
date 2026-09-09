package cdk_preflight

import rego.v1

# The name is the provider identifier the hosted UI uses, so it cannot be
# chosen freely for the built-in social providers.

violation contains make_diag_full("pf-cognito-idp-social-provider-name-fixed", "ERROR", name,
	"Properties.ProviderName",
	sprintf("ProviderName '%s' does not match ProviderType %s; the provider create fails with \"Provider %s cannot be of type %s.\"", [n, t, n, t]),
	"Name the provider exactly as its ProviderType (Google, Facebook, LoginWithAmazon, SignInWithApple)",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpoolidentityprovider.html") if {
	some name in resources_of_type("AWS::Cognito::UserPoolIdentityProvider")
	t := resolve(name, "Properties.ProviderType")
	t in _pf_coglib_social_idps
	n := resolve(name, "Properties.ProviderName")
	is_string(n)
	n != t
}
