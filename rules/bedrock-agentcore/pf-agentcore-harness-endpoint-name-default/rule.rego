package cdk_preflight

import rego.v1

# DEFAULT is reserved for the endpoint a harness owns implicitly, so an
# explicit HarnessEndpoint with that name is rejected (measured 2026-09-10).
# The schema pattern accepts DEFAULT. Sibling of
# pf-agentcore-runtime-endpoint-name-default on the Runtime side.
violation contains make_diag_full("pf-agentcore-harness-endpoint-name-default", "ERROR", name,
	"Properties.EndpointName",
	"EndpointName 'DEFAULT' is reserved; CreateHarnessEndpoint fails with \"Endpoint name 'DEFAULT' is reserved. Use a different name.\"",
	"Give the endpoint another name (for example prod)",
	"https://docs.aws.amazon.com/bedrock-agentcore-control/latest/APIReference/API_CreateHarnessEndpoint.html") if {
	some name in resources_of_type("AWS::BedrockAgentCore::HarnessEndpoint")
	resolve(name, "Properties.EndpointName") == "DEFAULT"
}
