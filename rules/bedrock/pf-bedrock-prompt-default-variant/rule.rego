package cdk_preflight

import rego.v1

# Documented ("This value must match the name field in the relevant
# PromptVariant") and enforced only by CreatePrompt (measured 2026-09-06).
violation contains make_diag_full("pf-bedrock-prompt-default-variant", "ERROR", name,
	"Properties.DefaultVariant",
	sprintf("DefaultVariant '%s' is not one of the variant names %v; CreatePrompt fails with \"Default variant must be present in the variants list\"", [dv, names]),
	"Set DefaultVariant to the Name of one of the Variants entries",
	"https://docs.aws.amazon.com/bedrock/latest/APIReference/API_agent_CreatePrompt.html") if {
	some name in resources_of_type("AWS::Bedrock::Prompt")
	dv := resolve(name, "Properties.DefaultVariant")
	is_string(dv)
	vs := object.get(_pf_bedrocklib_props(name), "Variants", [])
	is_array(vs)
	count(vs) > 0
	names := {v.Name | some v in vs; is_object(v); is_string(v.Name)}
	count(names) == count(vs)
	not names[dv]
}
