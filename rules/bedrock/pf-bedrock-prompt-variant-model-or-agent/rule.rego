package cdk_preflight

import rego.v1

# Both members are optional in the schema; CreatePrompt rejects the pair
# ("You can include either a modelId or a genAiResource, but not both",
# measured 2026-09-06).
violation contains make_diag_full("pf-bedrock-prompt-variant-model-or-agent", "ERROR", name,
	sprintf("Properties.Variants[%d].GenAiResource", [i]),
	sprintf("Variant '%s' sets both ModelId and GenAiResource; CreatePrompt fails with \"You can include either a modelId or a genAiResource, but not both\"", [v.Name]),
	"Remove ModelId (the agent supplies the model) or remove GenAiResource",
	"https://docs.aws.amazon.com/bedrock/latest/APIReference/API_agent_PromptVariant.html") if {
	some name in resources_of_type("AWS::Bedrock::Prompt")
	vs := object.get(_pf_bedrocklib_props(name), "Variants", [])
	some i, v in vs
	is_object(v)
	_pf_bedrocklib_has(v, "ModelId")
	_pf_bedrocklib_has(v, "GenAiResource")
}
