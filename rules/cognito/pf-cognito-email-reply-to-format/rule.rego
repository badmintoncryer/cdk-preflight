package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cognito-email-reply-to-format", "ERROR", name,
	"Properties.EmailConfiguration.ReplyToEmailAddress",
	sprintf("ReplyToEmailAddress '%s' is not an email address; the pool create fails with \"Member must satisfy regular expression pattern: [\\p{L}\\p{M}\\p{S}\\p{N}\\p{P}]+@[\\p{L}\\p{M}\\p{S}\\p{N}\\p{P}]+\"", [v]),
	"Use an address of the form user@example.com",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpool.html") if {
	some name in resources_of_type("AWS::Cognito::UserPool")
	v := resolve(name, "Properties.EmailConfiguration.ReplyToEmailAddress")
	is_string(v)
	not input.resources[v]
	not regex.match(`^[^@\s]+@[^@\s]+$`, v)
	not regex.match(`<[^@\s]+@[^@\s]+>$`, v)
}
