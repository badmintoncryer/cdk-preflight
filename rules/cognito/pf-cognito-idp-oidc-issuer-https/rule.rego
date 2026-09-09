package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cognito-idp-oidc-issuer-https", "ERROR", name,
	"Properties.ProviderDetails.oidc_issuer",
	sprintf("oidc_issuer '%s' is not https; the provider create fails with \"OIDC endpoint must start with https://\"", [v]),
	"Use an https:// issuer URL",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpoolidentityprovider.html") if {
	some name in resources_of_type("AWS::Cognito::UserPoolIdentityProvider")
	resolve(name, "Properties.ProviderType") == "OIDC"
	v := _pf_coglib_str(_pf_coglib_g2(name, "ProviderDetails", "oidc_issuer"))
	not startswith(v, "https://")
}
