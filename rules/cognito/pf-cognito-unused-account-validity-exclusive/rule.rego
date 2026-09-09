package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cognito-unused-account-validity-exclusive", "ERROR", name,
	"Properties.AdminCreateUserConfig.UnusedAccountValidityDays",
	"Both UnusedAccountValidityDays and PasswordPolicy.TemporaryPasswordValidityDays are set; the pool create fails with \"Please use TemporaryPasswordValidityDays in PasswordPolicy instead of UnusedAccountValidityDays\"",
	"Keep TemporaryPasswordValidityDays (the successor) and drop UnusedAccountValidityDays",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpool.html") if {
	some name in resources_of_type("AWS::Cognito::UserPool")
	_pf_coglib_set(_pf_coglib_g2(name, "AdminCreateUserConfig", "UnusedAccountValidityDays"))
	_pf_coglib_set(_pf_coglib_g3(name, "Policies", "PasswordPolicy", "TemporaryPasswordValidityDays"))
}
