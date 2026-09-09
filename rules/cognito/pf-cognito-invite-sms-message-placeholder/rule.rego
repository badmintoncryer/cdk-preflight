package cdk_preflight

import rego.v1

_pf_cgismp_bad(m) if not contains(m, "{####}")

_pf_cgismp_bad(m) if not contains(m, "{username}")

violation contains make_diag_full("pf-cognito-invite-sms-message-placeholder", "ERROR", name,
	"Properties.AdminCreateUserConfig.InviteMessageTemplate.SMSMessage",
	"The invite SMS message is missing {username} or {####}; the pool create fails on the adminCreateUserConfig.inviteMessage.smsMessage pattern",
	"Put both {username} and {####} in the invite SMS message",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpool.html") if {
	some name in resources_of_type("AWS::Cognito::UserPool")
	m := resolve(name, "Properties.AdminCreateUserConfig.InviteMessageTemplate.SMSMessage")
	is_string(m)
	_pf_cgismp_bad(m)
}
