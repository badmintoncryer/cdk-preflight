package cdk_preflight

import rego.v1

# The schema has no oneOf on AgentRuntimeArtifact (measured 2026-09-05: both
# blocks and an empty object pass the engine); CreateAgentRuntime rejects both
# shapes with "AgentArtifact must have exactly one configuration".
violation contains make_diag_full("pf-agentcore-runtime-artifact-exactly-one", "ERROR", name,
	"Properties.AgentRuntimeArtifact",
	sprintf("AgentRuntimeArtifact holds %d configurations; CreateAgentRuntime fails with \"AgentArtifact must have exactly one configuration\"", [n]),
	"Set exactly one of ContainerConfiguration (ECR image) or CodeConfiguration (S3 zip + EntryPoint + Runtime)",
	"https://docs.aws.amazon.com/bedrock-agentcore-control/latest/APIReference/API_AgentRuntimeArtifact.html") if {
	some name in resources_of_type("AWS::BedrockAgentCore::Runtime")
	props := input.resources[name].properties
	is_object(props)
	art := object.get(props, "AgentRuntimeArtifact", null)
	is_object(art)
	n := count([1 | some k in ["ContainerConfiguration", "CodeConfiguration"]; object.get(art, k, "__pf_absent") != "__pf_absent"])
	n != 1
}
