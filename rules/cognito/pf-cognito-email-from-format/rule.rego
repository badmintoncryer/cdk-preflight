package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cognito-email-from-format", "ERROR", name,
	"Properties.EmailConfiguration.From",
	sprintf("From '%s' is not an email address; the pool create fails with \"Provided From email address is invalid\"", [f]),
	"Use an address (user@example.com) or a display name form (\"Name <user@example.com>\")",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpool.html") if {
	some name in resources_of_type("AWS::Cognito::UserPool")
	f := resolve(name, "Properties.EmailConfiguration.From")
	is_string(f)
	not input.resources[f]
	not regex.match(`^[^@\s]+@[^@\s]+$`, f)
	not regex.match(`<[^@\s]+@[^@\s]+>$`, f)
}
