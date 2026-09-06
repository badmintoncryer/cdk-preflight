package cdk_preflight

import rego.v1

# The schema has no minItems/maxItems on Models; CreatePromptRouter accepts
# exactly two ("Prompt router limited to 2 models exactly", measured 2026-09-06).
violation contains make_diag_full("pf-bedrock-prompt-router-models-count", "ERROR", name,
	"Properties.Models",
	sprintf("Models lists %d entries; CreatePromptRouter fails with \"Prompt router limited to 2 models exactly\"", [n]),
	"List exactly two models (the fallback model must be one of them)",
	"https://docs.aws.amazon.com/bedrock/latest/APIReference/API_CreatePromptRouter.html") if {
	some name in resources_of_type("AWS::Bedrock::IntelligentPromptRouter")
	ms := object.get(_pf_bedrocklib_props(name), "Models", [])
	is_array(ms)
	n := count(ms)
	n != 2
}
