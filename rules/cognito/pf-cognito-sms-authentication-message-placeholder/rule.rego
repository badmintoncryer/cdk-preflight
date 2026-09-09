package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cognito-sms-authentication-message-placeholder", "ERROR", name,
	"Properties.SmsAuthenticationMessage",
	"SmsAuthenticationMessage has no {####} placeholder; the pool create fails on the smsAuthenticationMessage pattern",
	"Put {####} where the MFA code should appear",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpool.html") if {
	some name in resources_of_type("AWS::Cognito::UserPool")
	m := resolve(name, "Properties.SmsAuthenticationMessage")
	is_string(m)
	not contains(m, "{####}")
}
