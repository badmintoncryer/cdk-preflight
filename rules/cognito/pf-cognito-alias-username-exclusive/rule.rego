package cdk_preflight

import rego.v1

# Key presence is the violation regardless of values, so this checks the
# preprocessed document directly (see AGENTS.md).
_pf_cogaue_set(name, key) if {
	props := input.resources[name].properties
	is_object(props)
	object.get(props, key, "__pf_absent") != "__pf_absent"
}

violation contains make_diag_full("pf-cognito-alias-username-exclusive", "ERROR", name,
	"Properties.UsernameAttributes",
	"Both AliasAttributes and UsernameAttributes are set; the pool create fails with \"Only one of the aliasAttributes or usernameAttributes can be set in a User pool.\"",
	"Keep one: aliases for sign-in alternatives, or username attributes to replace usernames",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpool.html") if {
	some name in resources_of_type("AWS::Cognito::UserPool")
	_pf_cogaue_set(name, "AliasAttributes")
	_pf_cogaue_set(name, "UsernameAttributes")
}
