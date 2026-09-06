package cdk_preflight

import rego.v1

_pf_ggfu_items(name) := xs if {
	p := _pf_bedrocklib_props(name)
	xs := object.get(object.get(p, "ContextualGroundingPolicyConfig", {}), "FiltersConfig", [])
	is_array(xs)
}

_pf_ggfu_key(x) := k if {
	is_object(x)
	k := object.get(x, "Type", null)
	is_string(k)
}

violation contains make_diag_full("pf-bedrock-guardrail-grounding-filter-unique", "ERROR", name,
	sprintf("Properties.ContextualGroundingPolicyConfig.FiltersConfig[%d].Type", [i]),
	sprintf("Contextual grounding filter type '%s' appears more than once; CreateGuardrail fails with \"The Contextual Grounding policy cannot have duplicate types\"", [k]),
	"Keep one FiltersConfig entry each for GROUNDING and RELEVANCE",
	"https://docs.aws.amazon.com/bedrock/latest/APIReference/API_GuardrailContextualGroundingFilterConfig.html") if {
	some name in resources_of_type("AWS::Bedrock::Guardrail")
	xs := _pf_ggfu_items(name)
	some i, x in xs
	k := _pf_ggfu_key(x)
	some j, y in xs
	j < i
	_pf_ggfu_key(y) == k
}
