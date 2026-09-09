package cdk_preflight

import rego.v1

_pf_cguaurav_auto_verified(name, v) if {
	some b in flatten_list(name, "Properties.AutoVerifiedAttributes")
	b.value == v
}

violation contains make_diag_full("pf-cognito-user-attribute-update-requires-auto-verified", "ERROR", name,
	sprintf("Properties.UserAttributeUpdateSettings.AttributesRequireVerificationBeforeUpdate.%d", [a.index]),
	sprintf("'%s' requires verification before update but is not in AutoVerifiedAttributes; the pool create fails with \"All attributes in AttributesRequireVerificationBeforeUpdate must exist in AutoVerifiedAttributes\"", [v]),
	"Add the same attribute to AutoVerifiedAttributes",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpool.html") if {
	some name in resources_of_type("AWS::Cognito::UserPool")
	some a in flatten_list(name, "Properties.UserAttributeUpdateSettings.AttributesRequireVerificationBeforeUpdate")
	v := a.value
	is_string(v)
	not _pf_cguaurav_auto_verified(name, v)
}
