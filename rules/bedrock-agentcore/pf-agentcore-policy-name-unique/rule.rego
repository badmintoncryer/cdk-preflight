package cdk_preflight

import rego.v1

# CreatePolicy rejects a name already used on the same policy engine (409,
# measured 2026-09-10). E3019 reads primaryIdentifier, which is the read-only
# PolicyArn, so the PolicyEngineId + Name pair is invisible to the engine.
violation contains make_diag_full("pf-agentcore-policy-name-unique", "ERROR", name,
	"Properties.Name",
	sprintf("Policy name '%s' is already used by resource '%s' on the same policy engine; CreatePolicy fails with \"Policy with the same name already exists\"", [pName, other]),
	"Give each policy on an engine its own name",
	"https://docs.aws.amazon.com/bedrock-agentcore-control/latest/APIReference/API_CreatePolicy.html") if {
	some name in resources_of_type("AWS::BedrockAgentCore::Policy")
	pName := resolve(name, "Properties.Name")
	is_string(pName)
	eng := resolve(name, "Properties.PolicyEngineId")
	some other in resources_of_type("AWS::BedrockAgentCore::Policy")
	other < name
	resolve(other, "Properties.Name") == pName
	resolve(other, "Properties.PolicyEngineId") == eng
}
