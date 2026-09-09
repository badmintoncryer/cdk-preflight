package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cognito-mfa-off-with-enabled-mfas", "ERROR", name,
	"Properties.EnabledMfas",
	"MfaConfiguration is OFF but EnabledMfas lists MFA factors; the MFA config call rejects factors while MFA is off",
	"Set MfaConfiguration to ON or OPTIONAL, or drop EnabledMfas",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpool.html") if {
	some name in resources_of_type("AWS::Cognito::UserPool")
	resolve(name, "Properties.MfaConfiguration") == "OFF"
	count(flatten_list(name, "Properties.EnabledMfas")) > 0
}
