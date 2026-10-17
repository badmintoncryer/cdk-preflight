package cdk_preflight

import rego.v1

# The CapacityProviderArn pattern accepts any region, but CreateAgentRuntime
# looks the capacity provider up only in its own region: a READY capacity
# provider in us-west-2 is reported as "CapacityProvider '...' does not
# exist" (#354 B run2). data.cdk_preflight.deploy_region is defined only in
# enforce mode with a concrete region, otherwise this rule skips.
violation contains make_diag_full("pf-agentcore-runtime-capacity-provider-region", "ERROR", name,
	"Properties.CapacityProviderConfiguration.CapacityProviderArn",
	sprintf("The capacity provider lives in '%s' but the stack deploys to '%s'; CreateAgentRuntime looks it up only in its own region and fails with \"CapacityProvider ... does not exist\"", [r, region]),
	"Reference a capacity provider in the deploy region",
	"https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-instances.html") if {
	some name in resources_of_type("AWS::BedrockAgentCore::Runtime")
	region := data.cdk_preflight.deploy_region
	is_string(region)
	arn := resolve(name, "Properties.CapacityProviderConfiguration.CapacityProviderArn")
	is_string(arn)
	parts := split(arn, ":")
	count(parts) >= 6
	parts[2] == "bedrock-agentcore"
	r := parts[3]
	r != ""
	r != region
}
