package cdk_preflight

import rego.v1

# CreateEvaluator rejects a name already present in the account (409, measured
# 2026-09-10). The engine's duplicate check (E3019) reads primaryIdentifier,
# which is the read-only EvaluatorArn, so EvaluatorName is invisible to it.
violation contains make_diag_full("pf-agentcore-evaluator-name-unique", "ERROR", name,
	"Properties.EvaluatorName",
	sprintf("EvaluatorName '%s' is already used by resource '%s'; CreateEvaluator fails with \"Evaluator with same name already exist\"", [evName, other]),
	"Give each evaluator a distinct name",
	"https://docs.aws.amazon.com/bedrock-agentcore-control/latest/APIReference/API_CreateEvaluator.html") if {
	some name in resources_of_type("AWS::BedrockAgentCore::Evaluator")
	evName := resolve(name, "Properties.EvaluatorName")
	is_string(evName)
	some other in resources_of_type("AWS::BedrockAgentCore::Evaluator")
	other < name
	resolve(other, "Properties.EvaluatorName") == evName
}
