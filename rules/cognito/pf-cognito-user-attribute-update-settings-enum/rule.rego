package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cognito-user-attribute-update-settings-enum", "ERROR", name,
	sprintf("Properties.UserAttributeUpdateSettings.AttributesRequireVerificationBeforeUpdate.%d", [a.index]),
	sprintf("AttributesRequireVerificationBeforeUpdate has '%s'; the pool create fails with \"Member must satisfy enum value set: [phone_number, email]\"", [v]),
	"Keep AttributesRequireVerificationBeforeUpdate to email and/or phone_number",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpool.html") if {
	some name in resources_of_type("AWS::Cognito::UserPool")
	some a in flatten_list(name, "Properties.UserAttributeUpdateSettings.AttributesRequireVerificationBeforeUpdate")
	v := a.value
	is_string(v)
	not v in {"email", "phone_number"}
}
