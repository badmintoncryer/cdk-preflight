package cdk_preflight

import rego.v1

# The ARN pattern accepts any region, but CreateGateway rejects a policy
# engine from another region before looking it up ("Policy Engine ARN region
# 'us-west-2' does not match gateway region 'us-east-1'").
# data.cdk_preflight.deploy_region is defined only in enforce mode with a
# concrete region, otherwise this rule skips.
violation contains make_diag_full("pf-agentcore-gateway-policy-engine-region", "ERROR", name,
	"Properties.PolicyEngineConfiguration.Arn",
	sprintf("The policy engine lives in '%s' but the stack deploys to '%s'; CreateGateway fails with \"Policy Engine ARN region '%s' does not match gateway region '%s'\"", [r, region, r, region]),
	"Reference a policy engine in the deploy region",
	"https://docs.aws.amazon.com/bedrock-agentcore-control/latest/APIReference/API_GatewayPolicyEngineConfiguration.html") if {
	some name in resources_of_type("AWS::BedrockAgentCore::Gateway")
	region := data.cdk_preflight.deploy_region
	is_string(region)
	arn := resolve(name, "Properties.PolicyEngineConfiguration.Arn")
	is_string(arn)
	parts := split(arn, ":")
	count(parts) >= 6
	parts[2] == "bedrock-agentcore"
	r := parts[3]
	r != ""
	r != region
}
