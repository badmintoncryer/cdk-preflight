package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cognito-verification-code-placeholder", "ERROR", name,
	"Properties.VerificationMessageTemplate.EmailMessage",
	"VerificationMessageTemplate.EmailMessage has no {####} placeholder; the pool create fails on the emailMessage pattern",
	"Put {####} where the verification code should appear",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpool.html") if {
	some name in resources_of_type("AWS::Cognito::UserPool")
	m := resolve(name, "Properties.VerificationMessageTemplate.EmailMessage")
	is_string(m)
	not contains(m, "{####}")
}
