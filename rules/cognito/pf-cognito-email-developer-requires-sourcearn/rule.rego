package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cognito-email-developer-requires-sourcearn", "ERROR", name,
	"Properties.EmailConfiguration.SourceArn",
	"EmailSendingAccount is DEVELOPER but no SourceArn is set; the pool create fails with \"Source ARN is required to use DEVELOPER email sending owner\"",
	"Set EmailConfiguration.SourceArn to a verified SES identity, or use COGNITO_DEFAULT",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpool.html") if {
	some name in resources_of_type("AWS::Cognito::UserPool")
	_pf_coglib_g2(name, "EmailConfiguration", "EmailSendingAccount") == "DEVELOPER"
	_pf_coglib_absent(_pf_coglib_g2(name, "EmailConfiguration", "SourceArn"))
}
