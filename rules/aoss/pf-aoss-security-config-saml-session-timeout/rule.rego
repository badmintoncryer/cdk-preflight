package cdk_preflight

import rego.v1

# The CFN schema documents Minimum 5 / Maximum 720 but the bundled engine lets
# both ends through (checked with rule-check guard, 2026-09-25), so the stack
# reaches CreateSecurityConfig and rolls back there.

_pf_aoss_sto_fix := "Use a SessionTimeout between 5 and 720 minutes"

violation contains make_diag_full("pf-aoss-security-config-saml-session-timeout", "ERROR", name,
	"Properties.SamlOptions.SessionTimeout",
	sprintf("SessionTimeout is %v; CreateSecurityConfig answers \"Value '%v' at 'samlOptions.sessionTimeout' failed to satisfy constraint: Member must have value less than or equal to 720\"", [v, v]),
	_pf_aoss_sto_fix, "https://docs.aws.amazon.com/opensearch-service/latest/developerguide/serverless-saml.html") if {
	some name in resources_of_type("AWS::OpenSearchServerless::SecurityConfig")
	v := to_number(resolve(name, "Properties.SamlOptions.SessionTimeout"))
	v > 720
}

violation contains make_diag_full("pf-aoss-security-config-saml-session-timeout", "ERROR", name,
	"Properties.SamlOptions.SessionTimeout",
	sprintf("SessionTimeout is %v; CreateSecurityConfig answers \"Value '%v' at 'samlOptions.sessionTimeout' failed to satisfy constraint: Member must have value greater than or equal to 5\"", [v, v]),
	_pf_aoss_sto_fix, "https://docs.aws.amazon.com/opensearch-service/latest/developerguide/serverless-saml.html") if {
	some name in resources_of_type("AWS::OpenSearchServerless::SecurityConfig")
	v := to_number(resolve(name, "Properties.SamlOptions.SessionTimeout"))
	v < 5
}
