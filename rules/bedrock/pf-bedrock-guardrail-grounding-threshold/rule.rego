package cdk_preflight

import rego.v1

# The schema only sets minimum 0 on Threshold; CreateGuardrail rejects 1 and
# above ("cannot be greater than or equal to 1", measured 2026-09-06).
violation contains make_diag_full("pf-bedrock-guardrail-grounding-threshold", "ERROR", name,
	sprintf("Properties.ContextualGroundingPolicyConfig.FiltersConfig[%d].Threshold", [i]),
	sprintf("Contextual grounding threshold %v is not below 1; CreateGuardrail fails with \"grounding threshold cannot be greater than or equal to 1\"", [t]),
	"Use a threshold in the range 0 to 0.99",
	"https://docs.aws.amazon.com/bedrock/latest/APIReference/API_GuardrailContextualGroundingFilterConfig.html") if {
	some name in resources_of_type("AWS::Bedrock::Guardrail")
	p := _pf_bedrocklib_props(name)
	fs := object.get(object.get(p, "ContextualGroundingPolicyConfig", {}), "FiltersConfig", [])
	some i, f in fs
	is_object(f)
	t := to_number(f.Threshold)
	t >= 1
}
