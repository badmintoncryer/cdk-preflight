package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cognito-idp-saml-metadata-exclusive", "ERROR", name,
	"Properties.ProviderDetails.MetadataFile",
	"ProviderDetails has both MetadataURL and MetadataFile; the provider create fails with \"Only one of the MetadataURL or MetadataFile should be provided.\"",
	"Keep one metadata source: MetadataURL or MetadataFile",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpoolidentityprovider.html") if {
	some name in resources_of_type("AWS::Cognito::UserPoolIdentityProvider")
	resolve(name, "Properties.ProviderType") == "SAML"
	_pf_coglib_set(_pf_coglib_g2(name, "ProviderDetails", "MetadataURL"))
	_pf_coglib_set(_pf_coglib_g2(name, "ProviderDetails", "MetadataFile"))
}
