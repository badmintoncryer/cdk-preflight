package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cognito-email-verification-message-placeholder", "ERROR", name,
	"Properties.EmailVerificationMessage",
	"EmailVerificationMessage has no {####} placeholder; the pool create fails on the emailVerificationMessage pattern",
	"Put {####} where the verification code should appear",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpool.html") if {
	some name in resources_of_type("AWS::Cognito::UserPool")
	m := resolve(name, "Properties.EmailVerificationMessage")
	is_string(m)
	not contains(m, "{####}")
}
