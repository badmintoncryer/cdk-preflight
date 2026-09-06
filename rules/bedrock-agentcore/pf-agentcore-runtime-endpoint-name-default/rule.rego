package cdk_preflight

import rego.v1

# CreateAgentRuntime implicitly creates an endpoint named DEFAULT, so an
# explicit RuntimeEndpoint with that name always collides (409 AlreadyExists,
# measured 2026-09-06). The schema only checks the name pattern.
violation contains make_diag_full("pf-agentcore-runtime-endpoint-name-default", "ERROR", name,
	"Properties.Name",
	"Every AgentCore Runtime already owns an endpoint named DEFAULT, so this RuntimeEndpoint fails with \"An endpoint with the specified name already exists\" (409)",
	"Give the endpoint another name (for example prod), or drop the resource and invoke the runtime's built-in DEFAULT endpoint",
	"https://docs.aws.amazon.com/bedrock-agentcore-control/latest/APIReference/API_CreateAgentRuntimeEndpoint.html") if {
	some name in resources_of_type("AWS::BedrockAgentCore::RuntimeEndpoint")
	resolve(name, "Properties.Name") == "DEFAULT"
}
