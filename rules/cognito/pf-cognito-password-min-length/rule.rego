package cdk_preflight

import rego.v1

# The registry schema types MinimumLength as a bare integer; both bounds
# are deploy-verified.
_pf_cogpml_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-cognito-userpool-passwordpolicy.html"

violation contains make_diag_full("pf-cognito-password-min-length", "ERROR", name,
	"Properties.Policies.PasswordPolicy.MinimumLength",
	sprintf("MinimumLength %v is under the floor; the pool create fails with \"Member must have value greater than or equal to 6\"", [ml]),
	"Use a minimum password length between 6 and 99",
	_pf_cogpml_url) if {
	some name in resources_of_type("AWS::Cognito::UserPool")
	ml := to_number(resolve(name, "Properties.Policies.PasswordPolicy.MinimumLength"))
	ml < 6
}

violation contains make_diag_full("pf-cognito-password-min-length", "ERROR", name,
	"Properties.Policies.PasswordPolicy.MinimumLength",
	sprintf("MinimumLength %v is over the cap; the pool create fails with \"Member must have value less than or equal to 99\"", [ml]),
	"Use a minimum password length between 6 and 99",
	_pf_cogpml_url) if {
	some name in resources_of_type("AWS::Cognito::UserPool")
	ml := to_number(resolve(name, "Properties.Policies.PasswordPolicy.MinimumLength"))
	ml > 99
}
