package cdk_preflight

import rego.v1

# Measured constraint: the pairing is with SmsConfiguration, not with
# UsernameAttributes as the documentation prose suggests.

violation contains make_diag_full("pf-cognito-auto-verified-username-consistency", "ERROR", name,
	"Properties.AutoVerifiedAttributes",
	"AutoVerifiedAttributes has phone_number but the pool has no SmsConfiguration; the pool create fails with \"SMS configuration is required when phone_number is selected for auto verification\"",
	"Add SmsConfiguration (SnsCallerArn + ExternalId), or drop phone_number from AutoVerifiedAttributes",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpool.html") if {
	some name in resources_of_type("AWS::Cognito::UserPool")
	some a in flatten_list(name, "Properties.AutoVerifiedAttributes")
	a.value == "phone_number"
	_pf_coglib_absent(_pf_coglib_g1(name, "SmsConfiguration"))
}
