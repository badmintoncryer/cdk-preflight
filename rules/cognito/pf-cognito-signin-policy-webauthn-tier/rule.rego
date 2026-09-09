package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cognito-signin-policy-webauthn-tier", "ERROR", name,
	sprintf("Properties.Policies.SignInPolicy.AllowedFirstAuthFactors.%d", [f.index]),
	sprintf("first auth factor '%s' needs a paid feature tier but UserPoolTier is LITE; the pool create fails with \"The following features need to be disabled for the LITE pricing tier configured: Passwordless Sign-In\"", [f.value]),
	"Use UserPoolTier ESSENTIALS or PLUS, or keep PASSWORD as the only first auth factor",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpool.html") if {
	some name in resources_of_type("AWS::Cognito::UserPool")
	resolve(name, "Properties.UserPoolTier") == "LITE"
	some f in flatten_list(name, "Properties.Policies.SignInPolicy.AllowedFirstAuthFactors")
	f.value in {"WEB_AUTHN", "EMAIL_OTP", "SMS_OTP"}
}
