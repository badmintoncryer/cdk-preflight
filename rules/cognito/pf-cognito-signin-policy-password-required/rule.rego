package cdk_preflight

import rego.v1

_pf_cgsppr_has_password(fs) if {
	some f in fs
	f.value == "PASSWORD"
}

violation contains make_diag_full("pf-cognito-signin-policy-password-required", "ERROR", name,
	"Properties.Policies.SignInPolicy.AllowedFirstAuthFactors",
	"AllowedFirstAuthFactors does not include PASSWORD; the pool create fails with \"Password should be configured as one of the allowed first auth factors.\"",
	"Add PASSWORD to Policies.SignInPolicy.AllowedFirstAuthFactors",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpool.html") if {
	some name in resources_of_type("AWS::Cognito::UserPool")
	fs := flatten_list(name, "Properties.Policies.SignInPolicy.AllowedFirstAuthFactors")
	count(fs) > 0
	not _pf_cgsppr_has_password(fs)
}
