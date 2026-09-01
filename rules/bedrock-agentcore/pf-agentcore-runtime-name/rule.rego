package cdk_preflight

import rego.v1

# CloudFormation スキーマは AgentRuntimeName のパターンを持たない（エンジン素通り、
# 2026-09-01 に 1.7.0-beta で確認）が、CreateAgentRuntime API は
# [a-zA-Z][a-zA-Z0-9_]{0,47} を強制する。ハイフン入りの CDK 風命名が定番の死因。
violation contains make_diag_full("pf-agentcore-runtime-name", "ERROR", name,
	"Properties.AgentRuntimeName",
	sprintf("AgentRuntimeName '%s' is invalid: it must start with a letter and contain only letters, digits, and underscores (max 48 characters, hyphens are not allowed); CreateAgentRuntime fails at deploy time", [n]),
	"Use an underscore-separated name such as 'my_agent_runtime'",
	"https://docs.aws.amazon.com/bedrock-agentcore-control/latest/APIReference/API_CreateAgentRuntime.html") if {
	some name in resources_of_type("AWS::BedrockAgentCore::Runtime")
	n := resolve(name, "Properties.AgentRuntimeName")
	is_string(n)
	not regex.match(`^[a-zA-Z][a-zA-Z0-9_]{0,47}$`, n)
}
