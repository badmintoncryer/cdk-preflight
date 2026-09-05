package cdk_preflight

import rego.v1

# The schema checks each tool Name's pattern, not uniqueness. Duplicates are
# rejected asynchronously: the target reaches status FAILED ("Duplicate tool
# found in target configuration") and CloudFormation rolls back on
# NotStabilized minutes later.
_pf_gwttoolname_names(name) := [[t.index, n] |
	some t in flatten_list(name, "Properties.TargetConfiguration.Mcp.Lambda.ToolSchema.InlinePayload")
	n := object.get(t.value, "Name", null)
	is_string(n)
]

violation contains make_diag_full("pf-agentcore-gateway-target-lambda-tool-name-unique", "ERROR", name,
	sprintf("Properties.TargetConfiguration.Mcp.Lambda.ToolSchema.InlinePayload.%d.Name", [i]),
	sprintf("Tool name '%s' appears more than once; the target fails to stabilize with \"Duplicate tool found in target configuration\"", [n]),
	"Give every tool in the inline schema a distinct Name",
	"https://docs.aws.amazon.com/bedrock-agentcore-control/latest/APIReference/API_ToolDefinition.html") if {
	some name in resources_of_type("AWS::BedrockAgentCore::GatewayTarget")
	all := _pf_gwttoolname_names(name)
	some [i, n] in all
	count([1 | some [_, m] in all; m == n]) > 1
	i == max([j | some [j, m] in all; m == n])
}
