package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cognito-idp-provider-name-length", "ERROR", name,
	"Properties.ProviderName",
	sprintf("ProviderName is %d characters; the provider create fails with \"Member must have length less than or equal to 32\"", [count(n)]),
	"Use a provider name of at most 32 characters",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpoolidentityprovider.html") if {
	some name in resources_of_type("AWS::Cognito::UserPoolIdentityProvider")
	n := resolve(name, "Properties.ProviderName")
	is_string(n)
	not input.resources[n]
	count(n) > 32
}
