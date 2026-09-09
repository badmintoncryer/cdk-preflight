package cdk_preflight

import rego.v1

_pf_cguavr_bad(v) if v < 0

_pf_cguavr_bad(v) if v > 365

violation contains make_diag_full("pf-cognito-unused-account-validity-range", "ERROR", name,
	"Properties.AdminCreateUserConfig.UnusedAccountValidityDays",
	sprintf("UnusedAccountValidityDays %v is outside 0-365; the pool create fails with \"Member must have value less than or equal to 365\"", [v]),
	"Use a value between 0 and 365 days",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpool.html") if {
	some name in resources_of_type("AWS::Cognito::UserPool")
	v := to_number(resolve(name, "Properties.AdminCreateUserConfig.UnusedAccountValidityDays"))
	_pf_cguavr_bad(v)
}
