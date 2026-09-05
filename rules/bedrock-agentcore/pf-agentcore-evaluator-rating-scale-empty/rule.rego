package cdk_preflight

import rego.v1

# RatingScale is a oneOf (Numerical | Categorical) in the schema, which catches
# both-or-neither (F3018), but neither array carries minItems: an empty
# Categorical / Numerical list passes validation and CreateEvaluator rejects it
# with "RatingScale must contain at least one non-empty scale definition".
violation contains make_diag_full("pf-agentcore-evaluator-rating-scale-empty", "ERROR", name,
	sprintf("Properties.EvaluatorConfig.LlmAsAJudge.RatingScale.%s", [key]),
	sprintf("RatingScale.%s is empty; CreateEvaluator fails with \"RatingScale must contain at least one non-empty scale definition (numerical or categorical)\"", [key]),
	"List at least one scale entry (Label, Definition, and Value for Numerical)",
	"https://docs.aws.amazon.com/bedrock-agentcore-control/latest/APIReference/API_RatingScale.html") if {
	some name in resources_of_type("AWS::BedrockAgentCore::Evaluator")
	some key in ["Numerical", "Categorical"]
	arr := resolve(name, sprintf("Properties.EvaluatorConfig.LlmAsAJudge.RatingScale.%s", [key]))
	is_array(arr)
	count(arr) == 0
}
