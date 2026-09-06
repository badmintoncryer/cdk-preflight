package cdk_preflight

import rego.v1

# Variable types are the names of PolicyDefinition.Types entries, nothing else
# (even bool/int/real/string are rejected, measured 2026-09-06).
violation contains make_diag_full("pf-bedrock-automated-reasoning-policy-variable-type", "ERROR", name,
	sprintf("Properties.PolicyDefinition.Variables[%d].Type", [i]),
	sprintf("Variable '%s' uses type '%s', which PolicyDefinition.Types does not declare; CreateAutomatedReasoningPolicy fails with \"Variable … uses a type that is not defined\"", [v.Name, t]),
	"Declare the type under PolicyDefinition.Types (Name + Values) and reference that Name",
	"https://docs.aws.amazon.com/bedrock/latest/APIReference/API_AutomatedReasoningPolicyDefinitionVariable.html") if {
	some name in resources_of_type("AWS::Bedrock::AutomatedReasoningPolicy")
	pd := object.get(_pf_bedrocklib_props(name), "PolicyDefinition", {})
	types := {x.Name | some x in object.get(pd, "Types", []); is_object(x); is_string(x.Name)}
	some i, v in object.get(pd, "Variables", [])
	is_object(v)
	t := v.Type
	is_string(t)
	not types[t]
}
