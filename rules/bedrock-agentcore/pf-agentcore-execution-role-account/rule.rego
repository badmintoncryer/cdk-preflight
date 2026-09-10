package cdk_preflight

import rego.v1

# AgentCore assumes the execution role through the caller's own account, so a
# role ARN in another account is refused - and it surfaces as a 403 on the
# create call ("User ... is not authorized to perform:
# bedrock-agentcore:CreateOnlineEvaluationConfig"), which reads like a missing
# IAM permission rather than a wrong ARN (measured 2026-09-10; the same
# template with a local role reaches CREATE_COMPLETE).
# data.cdk_preflight.deploy_account is defined only in enforce mode with a
# concrete account, otherwise this rule skips.
_pf_acrole_props := [
	["AWS::BedrockAgentCore::OnlineEvaluationConfig", "EvaluationExecutionRoleArn"],
	["AWS::BedrockAgentCore::Memory", "MemoryExecutionRoleArn"],
]

violation contains make_diag_full("pf-agentcore-execution-role-account", "ERROR", name,
	sprintf("Properties.%s", [pair[1]]),
	sprintf("%s names a role in account '%s' but the stack deploys to '%s'; the create call fails with a 403 \"not authorized to perform\" that looks like a missing permission", [pair[1], roleAccount, account]),
	"Reference a role in the deploy account",
	"https://docs.aws.amazon.com/bedrock-agentcore-control/latest/APIReference/API_CreateOnlineEvaluationConfig.html") if {
	some pair in _pf_acrole_props
	some name in resources_of_type(pair[0])
	account := data.cdk_preflight.deploy_account
	is_string(account)
	arn := resolve(name, sprintf("Properties.%s", [pair[1]]))
	is_string(arn)
	parts := split(arn, ":")
	count(parts) >= 6
	parts[0] == "arn"
	parts[2] == "iam"
	roleAccount := parts[4]
	roleAccount != ""
	roleAccount != account
}
