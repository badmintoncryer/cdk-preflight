package cdk_preflight

import rego.v1

# The schema bounds Evaluators (1..10) and each EvaluatorId's pattern, not
# uniqueness; CreateOnlineEvaluationConfig rejects repeats with
# "Duplicate evaluator ids detected".
_pf_oeevdup_ids(name) := [[e.index, id] |
	some e in flatten_list(name, "Properties.Evaluators")
	id := object.get(e.value, "EvaluatorId", null)
	is_string(id)
]

violation contains make_diag_full("pf-agentcore-online-eval-evaluator-unique", "ERROR", name,
	sprintf("Properties.Evaluators.%d.EvaluatorId", [i]),
	sprintf("Evaluator '%s' is listed more than once; CreateOnlineEvaluationConfig fails with \"Duplicate evaluator ids detected\"", [id]),
	"List each evaluator once",
	"https://docs.aws.amazon.com/bedrock-agentcore-control/latest/APIReference/API_CreateOnlineEvaluationConfig.html") if {
	some name in resources_of_type("AWS::BedrockAgentCore::OnlineEvaluationConfig")
	all := _pf_oeevdup_ids(name)
	some [i, id] in all
	count([1 | some [_, o] in all; o == id]) > 1
	i == max([j | some [j, o] in all; o == id])
}
