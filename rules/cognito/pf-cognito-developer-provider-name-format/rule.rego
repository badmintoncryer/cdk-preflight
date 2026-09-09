package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cognito-developer-provider-name-format", "ERROR", name,
	"Properties.DeveloperProviderName",
	sprintf("DeveloperProviderName '%s' has characters outside [\\w._-]; the identity pool create fails with \"Member must satisfy regular expression pattern: [\\w._-]+\"", [v]),
	"Use letters, digits, dots, underscores and hyphens only",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-identitypool.html") if {
	some name in resources_of_type("AWS::Cognito::IdentityPool")
	v := resolve(name, "Properties.DeveloperProviderName")
	is_string(v)
	not input.resources[v]
	not regex.match(`^[\w._-]+$`, v)
}
