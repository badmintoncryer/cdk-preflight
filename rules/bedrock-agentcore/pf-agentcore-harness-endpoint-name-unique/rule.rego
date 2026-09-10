package cdk_preflight

import rego.v1

# Two endpoints with the same name on one harness collide (measured
# 2026-09-10). E3019 reads primaryIdentifier, which here is the read-only
# Arn, so the HarnessId + EndpointName pair is invisible to the engine.
violation contains make_diag_full("pf-agentcore-harness-endpoint-name-unique", "ERROR", name,
	"Properties.EndpointName",
	sprintf("EndpointName '%s' is already used by resource '%s' on the same harness; CreateHarnessEndpoint fails with \"A resource with the same resourceName but a different internalId already exists\"", [ep, other]),
	"Give each endpoint on a harness its own name",
	"https://docs.aws.amazon.com/bedrock-agentcore-control/latest/APIReference/API_CreateHarnessEndpoint.html") if {
	some name in resources_of_type("AWS::BedrockAgentCore::HarnessEndpoint")
	ep := resolve(name, "Properties.EndpointName")
	is_string(ep)
	h := resolve(name, "Properties.HarnessId")
	some other in resources_of_type("AWS::BedrockAgentCore::HarnessEndpoint")
	other < name
	resolve(other, "Properties.EndpointName") == ep
	resolve(other, "Properties.HarnessId") == h
}
