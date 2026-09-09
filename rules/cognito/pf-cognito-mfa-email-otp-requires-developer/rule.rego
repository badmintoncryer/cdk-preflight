package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cognito-mfa-email-otp-requires-developer", "ERROR", name,
	"Properties.EnabledMfas",
	"EnabledMfas has EMAIL_OTP but EmailConfiguration.EmailSendingAccount is not DEVELOPER; the pool create fails with \"Cannot set EmailMfaConfiguration when user pool EmailConfiguration contains an EmailSendingAccount of COGNITO_DEFAULT.\"",
	"Set EmailConfiguration.EmailSendingAccount to DEVELOPER with a SES SourceArn, or drop EMAIL_OTP",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpool.html") if {
	some name in resources_of_type("AWS::Cognito::UserPool")
	some a in flatten_list(name, "Properties.EnabledMfas")
	a.value == "EMAIL_OTP"
	_pf_coglib_g2(name, "EmailConfiguration", "EmailSendingAccount") != "DEVELOPER"
}
