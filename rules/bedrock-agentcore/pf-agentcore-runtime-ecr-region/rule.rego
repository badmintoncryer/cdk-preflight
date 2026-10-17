package cdk_preflight

import rego.v1

# The ContainerUri pattern accepts any ECR region. CreateAgentRuntime rejects
# a repository in another region before it looks the image up ("Ecr uri region
# 'us-west-2' does not match the application region 'us-east-1'"). The account
# part of the URI is not measured and not checked.
# data.cdk_preflight.deploy_region is defined only in enforce mode with a
# concrete region, otherwise this rule skips.
violation contains make_diag_full("pf-agentcore-runtime-ecr-region", "ERROR", name,
	"Properties.AgentRuntimeArtifact.ContainerConfiguration.ContainerUri",
	sprintf("The image lives in ECR '%s' but the stack deploys to '%s'; CreateAgentRuntime fails with \"Ecr uri region '%s' does not match the application region '%s'\"", [r, region, r, region]),
	"Push or replicate the image to an ECR repository in the deploy region (a pull-through cache rule works for public images)",
	"https://docs.aws.amazon.com/bedrock-agentcore-control/latest/APIReference/API_CreateAgentRuntime.html") if {
	some name in resources_of_type("AWS::BedrockAgentCore::Runtime")
	region := data.cdk_preflight.deploy_region
	is_string(region)
	uri := resolve(name, "Properties.AgentRuntimeArtifact.ContainerConfiguration.ContainerUri")
	is_string(uri)
	m := regex.find_all_string_submatch_n(`^[^./]+\.dkr\.ecr\.([a-z0-9-]+)\.amazonaws\.com/`, uri, 1)
	count(m) == 1
	r := m[0][1]
	r != region
}
