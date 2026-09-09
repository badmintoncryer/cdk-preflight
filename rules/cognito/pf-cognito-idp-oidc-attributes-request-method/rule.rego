package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cognito-idp-oidc-attributes-request-method", "ERROR", name,
	"Properties.ProviderDetails.attributes_request_method",
	sprintf("attributes_request_method '%s' is not GET or POST; the provider create fails with \"Member must satisfy enum value set: [POST, GET]\"", [v]),
	"Set ProviderDetails.attributes_request_method to GET or POST",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpoolidentityprovider.html") if {
	some name in resources_of_type("AWS::Cognito::UserPoolIdentityProvider")
	resolve(name, "Properties.ProviderType") == "OIDC"
	v := _pf_coglib_str(_pf_coglib_g2(name, "ProviderDetails", "attributes_request_method"))
	not v in {"GET", "POST"}
}
