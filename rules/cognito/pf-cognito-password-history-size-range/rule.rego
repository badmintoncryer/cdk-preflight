package cdk_preflight

import rego.v1

_pf_cgphsr_bad(v) if v < 0

_pf_cgphsr_bad(v) if v > 24

violation contains make_diag_full("pf-cognito-password-history-size-range", "ERROR", name,
	"Properties.Policies.PasswordPolicy.PasswordHistorySize",
	sprintf("PasswordHistorySize %v is outside 0-24; the pool create fails with \"Member must have value less than or equal to 24\"", [v]),
	"Use a password history size between 0 and 24",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpool.html") if {
	some name in resources_of_type("AWS::Cognito::UserPool")
	v := to_number(resolve(name, "Properties.Policies.PasswordPolicy.PasswordHistorySize"))
	_pf_cgphsr_bad(v)
}
