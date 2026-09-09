package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cognito-idp-saml-metadata-required", "ERROR", name,
	"Properties.ProviderDetails",
	"ProviderType is SAML but ProviderDetails has neither MetadataURL nor MetadataFile; the provider create fails with \"At least one of the MetadataURL or MetadataFile should be provided.\"",
	"Set ProviderDetails.MetadataURL or ProviderDetails.MetadataFile",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpoolidentityprovider.html") if {
	some name in resources_of_type("AWS::Cognito::UserPoolIdentityProvider")
	resolve(name, "Properties.ProviderType") == "SAML"
	_pf_coglib_absent(_pf_coglib_g2(name, "ProviderDetails", "MetadataURL"))
	_pf_coglib_absent(_pf_coglib_g2(name, "ProviderDetails", "MetadataFile"))
}
