package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cognito-verification-link-placeholder", "ERROR", name,
	"Properties.VerificationMessageTemplate.EmailMessageByLink",
	"DefaultEmailOption is CONFIRM_WITH_LINK but EmailMessageByLink has no {##...##} link placeholder; the pool create fails on the emailMessageByLink pattern",
	"Wrap the link text in {## and ##}, e.g. \"Click {##here##} to verify\"",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpool.html") if {
	some name in resources_of_type("AWS::Cognito::UserPool")
	resolve(name, "Properties.VerificationMessageTemplate.DefaultEmailOption") == "CONFIRM_WITH_LINK"
	m := resolve(name, "Properties.VerificationMessageTemplate.EmailMessageByLink")
	is_string(m)
	not regex.match(`\{##.*##\}`, m)
}
