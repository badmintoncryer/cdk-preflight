package cdk_preflight

import rego.v1

# Evaluators and Insights are both optional in the schema and Evaluators has
# no minItems; CreateOnlineEvaluationConfig requires exactly one of them to be
# non-empty ("Exactly one of evaluators or insights must be provided").
_pf_oeevs_nonempty(props, key) if {
	v := object.get(props, key, null)
	is_array(v)
	count(v) > 0
}

violation contains make_diag_full("pf-agentcore-online-eval-evaluators-or-insights", "ERROR", name,
	"Properties.Evaluators",
	"Neither Evaluators nor Insights lists anything; CreateOnlineEvaluationConfig fails with \"Exactly one of evaluators or insights must be provided\"",
	"List at least one evaluator (e.g. EvaluatorId Builtin.Helpfulness) or configure Insights",
	"https://docs.aws.amazon.com/bedrock-agentcore-control/latest/APIReference/API_CreateOnlineEvaluationConfig.html") if {
	some name in resources_of_type("AWS::BedrockAgentCore::OnlineEvaluationConfig")
	props := input.resources[name].properties
	is_object(props)
	not _pf_oeevs_nonempty(props, "Evaluators")
	not _pf_oeevs_nonempty(props, "Insights")
}
