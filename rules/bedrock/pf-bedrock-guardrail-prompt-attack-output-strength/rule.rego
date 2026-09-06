package cdk_preflight

import rego.v1

# The schema gives every filter the same NONE|LOW|MEDIUM|HIGH enum for both
# strengths; only CreateGuardrail knows that prompt attacks are an input-only
# check ("PROMPT ATTACK content filter strength for response must be NONE",
# measured 2026-09-06).
violation contains make_diag_full("pf-bedrock-guardrail-prompt-attack-output-strength", "ERROR", name,
	sprintf("Properties.ContentPolicyConfig.FiltersConfig[%d].OutputStrength", [i]),
	sprintf("The PROMPT_ATTACK content filter has OutputStrength '%s'; CreateGuardrail fails with \"PROMPT ATTACK content filter strength for response must be NONE\"", [s]),
	"Set OutputStrength: NONE on the PROMPT_ATTACK filter (prompt attacks are only evaluated on the input side)",
	"https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-content-filters.html") if {
	some name in resources_of_type("AWS::Bedrock::Guardrail")
	p := _pf_bedrocklib_props(name)
	fs := object.get(object.get(p, "ContentPolicyConfig", {}), "FiltersConfig", [])
	some i, f in fs
	is_object(f)
	f.Type == "PROMPT_ATTACK"
	s := f.OutputStrength
	is_string(s)
	s != "NONE"
}
