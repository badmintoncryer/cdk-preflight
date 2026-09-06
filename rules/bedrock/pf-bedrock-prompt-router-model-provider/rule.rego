package cdk_preflight

import rego.v1

# Routing works "between different foundational models within the same model
# family"; CreatePromptRouter rejects a mix of providers (measured 2026-09-06).
# Provider = model id prefix (behind an optional us./eu./apac. geo prefix).
violation contains make_diag_full("pf-bedrock-prompt-router-model-provider", "ERROR", name,
	"Properties.Models",
	sprintf("Models mix providers %v; CreatePromptRouter fails with \"is from a different provider than the other models\"", [provs]),
	"Route between two models of the same provider (e.g. two Anthropic Claude models)",
	"https://docs.aws.amazon.com/bedrock/latest/userguide/prompt-routing.html") if {
	some name in resources_of_type("AWS::Bedrock::IntelligentPromptRouter")
	ms := object.get(_pf_bedrocklib_props(name), "Models", [])
	provs := {pr | some m in ms; is_object(m); pr := _pf_bedrocklib_model_provider(m.ModelArn)}
	count(provs) > 1
}
