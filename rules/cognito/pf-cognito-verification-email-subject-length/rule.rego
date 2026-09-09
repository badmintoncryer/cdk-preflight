package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cognito-verification-email-subject-length", "ERROR", name,
	"Properties.VerificationMessageTemplate.EmailSubject",
	sprintf("EmailSubject is %d characters; the pool create fails with \"Member must have length less than or equal to 140\"", [count(s)]),
	"Shorten the subject to 140 characters or fewer",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpool.html") if {
	some name in resources_of_type("AWS::Cognito::UserPool")
	s := resolve(name, "Properties.VerificationMessageTemplate.EmailSubject")
	is_string(s)
	count(s) > 140
}
