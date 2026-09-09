package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cognito-email-cognito-default-with-sourcearn", "ERROR", name,
	"Properties.EmailConfiguration.SourceArn",
	"EmailSendingAccount is COGNITO_DEFAULT but a SourceArn is set; the pool create fails with \"Cognito is not allowed to use your email identity\"",
	"Switch EmailSendingAccount to DEVELOPER, or drop SourceArn",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpool.html") if {
	some name in resources_of_type("AWS::Cognito::UserPool")
	_pf_coglib_g2(name, "EmailConfiguration", "EmailSendingAccount") == "COGNITO_DEFAULT"
	_pf_coglib_set(_pf_coglib_g2(name, "EmailConfiguration", "SourceArn"))
}
