package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cognito-idp-oidc-required-keys", "ERROR", name,
	sprintf("Properties.ProviderDetails.%s", [k]),
	sprintf("OIDC ProviderDetails has no %s; the provider create fails with \"clientId, authorizeScopes, oidcIssuer and attributesRequestMethod are all required idp details.\"", [k]),
	"Set client_id, authorize_scopes, oidc_issuer and attributes_request_method",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpoolidentityprovider.html") if {
	some name in resources_of_type("AWS::Cognito::UserPoolIdentityProvider")
	resolve(name, "Properties.ProviderType") == "OIDC"
	some k in ["client_id", "authorize_scopes", "oidc_issuer", "attributes_request_method"]
	_pf_coglib_absent(_pf_coglib_g2(name, "ProviderDetails", k))
}
