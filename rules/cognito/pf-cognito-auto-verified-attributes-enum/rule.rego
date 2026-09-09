package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cognito-auto-verified-attributes-enum", "ERROR", name,
	sprintf("Properties.AutoVerifiedAttributes.%d", [a.index]),
	sprintf("AutoVerifiedAttributes has '%s'; the pool create fails with \"Member must satisfy enum value set: [phone_number, email]\"", [v]),
	"Keep AutoVerifiedAttributes to email and/or phone_number",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpool.html") if {
	some name in resources_of_type("AWS::Cognito::UserPool")
	some a in flatten_list(name, "Properties.AutoVerifiedAttributes")
	v := a.value
	is_string(v)
	not v in {"email", "phone_number"}
}
