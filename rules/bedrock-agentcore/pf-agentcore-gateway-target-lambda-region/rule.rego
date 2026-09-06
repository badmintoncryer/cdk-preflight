package cdk_preflight

import rego.v1

# CreateGatewayTarget resolves the Lambda ARN only in the gateway's own
# region: a function that really exists in another region is rejected with
# the same "Lambda function not found" as a typo (measured 2026-09-06 with a
# live function in us-west-2). data.cdk_preflight.deploy_region is defined
# only in enforce mode with a concrete region; otherwise this rule skips.
violation contains make_diag_full("pf-agentcore-gateway-target-lambda-region", "ERROR", name,
	"Properties.TargetConfiguration.Mcp.Lambda.LambdaArn",
	sprintf("The Lambda target lives in '%s' but the gateway deploys to '%s'; CreateGatewayTarget only resolves functions in its own region and fails with \"Lambda function not found\"", [fnRegion, region]),
	"Deploy the function in the gateway's region (or the gateway in the function's region) and reference that ARN",
	"https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-building-adding-targets.html") if {
	some name in resources_of_type("AWS::BedrockAgentCore::GatewayTarget")
	region := data.cdk_preflight.deploy_region
	is_string(region)
	arn := resolve(name, "Properties.TargetConfiguration.Mcp.Lambda.LambdaArn")
	is_string(arn)
	parts := split(arn, ":")
	count(parts) >= 7
	parts[0] == "arn"
	parts[2] == "lambda"
	fnRegion := parts[3]
	fnRegion != ""
	fnRegion != region
}
