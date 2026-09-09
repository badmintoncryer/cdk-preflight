package cdk_preflight

import rego.v1

# Asymmetric with OIDC: OpenIdConnectProviderARNs from another account are
# accepted, SAML ones are not (measured 2026-09-08).

violation contains make_diag_full("pf-cognito-identity-pool-saml-arn-account", "ERROR", name,
	sprintf("Properties.SamlProviderARNs.%d", [s.index]),
	sprintf("the SAML provider is in account %v but the identity pool deploys to %v; the create fails with \"Identity provider %v is not valid for account %v\"", [a, acct, arn, acct]),
	"Use an IAM SAML provider from the same account as the identity pool",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-identitypool.html") if {
	some name in resources_of_type("AWS::Cognito::IdentityPool")
	acct := data.cdk_preflight.deploy_account
	is_string(acct)
	some s in flatten_list(name, "Properties.SamlProviderARNs")
	arn := s.value
	a := _pf_coglib_arn_account(arn)
	a != acct
}
