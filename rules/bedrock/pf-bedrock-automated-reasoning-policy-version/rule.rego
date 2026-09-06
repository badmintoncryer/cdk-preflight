package cdk_preflight

import rego.v1

# The schema types Version as a free string; the service recognises only
# "1.0" (measured 2026-09-06; omitting it is fine).
violation contains make_diag_full("pf-bedrock-automated-reasoning-policy-version", "ERROR", name,
	"Properties.PolicyDefinition.Version",
	sprintf("PolicyDefinition.Version '%s' is not a recognised definition version; CreateAutomatedReasoningPolicy fails with \"Unrecognized version\"", [v]),
	"Set Version to \"1.0\" or omit it",
	"https://docs.aws.amazon.com/bedrock/latest/APIReference/API_AutomatedReasoningPolicyDefinition.html") if {
	some name in resources_of_type("AWS::Bedrock::AutomatedReasoningPolicy")
	v := resolve(name, "Properties.PolicyDefinition.Version")
	is_string(v)
	v != "1.0"
}
