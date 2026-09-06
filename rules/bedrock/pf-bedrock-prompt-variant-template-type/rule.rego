package cdk_preflight

import rego.v1

# The schema's oneOf only guarantees a single TemplateConfiguration member;
# the pairing with TemplateType is checked by CreatePrompt (measured 2026-09-06).
_pf_pvtt_member := {"TEXT": "Text", "CHAT": "Chat"}

violation contains make_diag_full("pf-bedrock-prompt-variant-template-type", "ERROR", name,
	sprintf("Properties.Variants[%d].TemplateConfiguration", [i]),
	sprintf("Variant '%s' has TemplateType %s but no TemplateConfiguration.%s; CreatePrompt fails with \"%sTemplateConfig cannot be null when PromptTemplateType is %s\"", [v.Name, t, m, lower(m), t]),
	sprintf("Provide TemplateConfiguration.%s, or change TemplateType", [m]),
	"https://docs.aws.amazon.com/bedrock/latest/APIReference/API_agent_PromptVariant.html") if {
	some name in resources_of_type("AWS::Bedrock::Prompt")
	vs := object.get(_pf_bedrocklib_props(name), "Variants", [])
	some i, v in vs
	is_object(v)
	t := v.TemplateType
	m := _pf_pvtt_member[t]
	tc := object.get(v, "TemplateConfiguration", null)
	is_object(tc)
	not _pf_bedrocklib_has(tc, m)
}
