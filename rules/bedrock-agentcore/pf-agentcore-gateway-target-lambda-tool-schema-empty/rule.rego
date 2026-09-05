package cdk_preflight

import rego.v1

# InlinePayload has no minItems in the schema; the service rejects an empty
# tool list with "No Lambda tool schema found in target configuration".
violation contains make_diag_full("pf-agentcore-gateway-target-lambda-tool-schema-empty", "ERROR", name,
	"Properties.TargetConfiguration.Mcp.Lambda.ToolSchema.InlinePayload",
	"The Lambda target declares an empty tool list; CreateGatewayTarget fails with \"No Lambda tool schema found in target configuration\"",
	"Declare at least one tool (Name, Description, InputSchema) or point ToolSchema.S3 at a schema file",
	"https://docs.aws.amazon.com/bedrock-agentcore-control/latest/APIReference/API_ToolDefinition.html") if {
	some name in resources_of_type("AWS::BedrockAgentCore::GatewayTarget")
	tools := resolve(name, "Properties.TargetConfiguration.Mcp.Lambda.ToolSchema.InlinePayload")
	is_array(tools)
	count(tools) == 0
}
