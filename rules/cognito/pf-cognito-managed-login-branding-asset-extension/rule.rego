package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cognito-managed-login-branding-asset-extension", "ERROR", name,
	sprintf("Properties.Assets.%d.Extension", [a.index]),
	sprintf("asset category %s carries an ICO file; ICO is only valid for the FAVICON_ICO category", [cat]),
	"Use PNG, JPEG, SVG or WEBP for page assets; ICO only for FAVICON_ICO",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-managedloginbranding.html") if {
	some name in resources_of_type("AWS::Cognito::ManagedLoginBranding")
	some a in flatten_list(name, "Properties.Assets")
	is_object(a.value)
	cat := object.get(a.value, "Category", "")
	object.get(a.value, "Extension", "") == "ICO"
	cat != "FAVICON_ICO"
}
