package cdk_preflight

import rego.v1

# Every policy block is optional in the schema; CreateGuardrail needs at least
# one ("Guardrail must have at least one policy", measured 2026-09-06).
_pf_gpol_keys := ["ContentPolicyConfig", "TopicPolicyConfig", "WordPolicyConfig", "SensitiveInformationPolicyConfig", "ContextualGroundingPolicyConfig", "AutomatedReasoningPolicyConfig"]

violation contains make_diag_full("pf-bedrock-guardrail-policy-required", "ERROR", name,
	"Properties",
	"The guardrail configures no policy; CreateGuardrail fails with \"Guardrail must have at least one policy\"",
	"Add at least one of ContentPolicyConfig, TopicPolicyConfig, WordPolicyConfig, SensitiveInformationPolicyConfig, ContextualGroundingPolicyConfig or AutomatedReasoningPolicyConfig",
	"https://docs.aws.amazon.com/bedrock/latest/APIReference/API_CreateGuardrail.html") if {
	some name in resources_of_type("AWS::Bedrock::Guardrail")
	p := _pf_bedrocklib_props(name)
	count([k | some k in _pf_gpol_keys; _pf_bedrocklib_has(p, k)]) == 0
}
