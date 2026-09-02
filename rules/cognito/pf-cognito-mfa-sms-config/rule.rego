package cdk_preflight

import rego.v1

# With MFA on and no EnabledMfas, Cognito falls back to SMS MFA, which
# needs SmsConfiguration. A pool declaring EnabledMfas (e.g. TOTP only,
# bench c05b) is valid without SMS, so its presence mutes the rule.
# Absence is proven against the preprocessed document (see AGENTS.md).
_pf_cogmsc_absent(name, key) if {
	props := input.resources[name].properties
	is_object(props)
	object.get(props, key, "__pf_absent") == "__pf_absent"
}

violation contains make_diag_full("pf-cognito-mfa-sms-config", "ERROR", name,
	"Properties.MfaConfiguration",
	sprintf("MfaConfiguration '%s' with no SmsConfiguration and no EnabledMfas; the pool create fails with \"SMS configuration and Auto verification for phone_number are required when MFA is required/optional\"", [mfa]),
	"Configure SmsConfiguration (SMS MFA), or pick factors via EnabledMfas (e.g. SOFTWARE_TOKEN_MFA)",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpool.html") if {
	some name in resources_of_type("AWS::Cognito::UserPool")
	mfa := resolve(name, "Properties.MfaConfiguration")
	mfa in {"ON", "OPTIONAL"}
	_pf_cogmsc_absent(name, "SmsConfiguration")
	_pf_cogmsc_absent(name, "EnabledMfas")
}
