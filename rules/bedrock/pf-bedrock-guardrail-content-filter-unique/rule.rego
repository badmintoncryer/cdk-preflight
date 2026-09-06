package cdk_preflight

import rego.v1

_pf_gcfu_items(name) := xs if {
	p := _pf_bedrocklib_props(name)
	xs := object.get(object.get(p, "ContentPolicyConfig", {}), "FiltersConfig", [])
	is_array(xs)
}

_pf_gcfu_key(x) := k if {
	is_object(x)
	k := object.get(x, "Type", null)
	is_string(k)
}

violation contains make_diag_full("pf-bedrock-guardrail-content-filter-unique", "ERROR", name,
	sprintf("Properties.ContentPolicyConfig.FiltersConfig[%d].Type", [i]),
	sprintf("Content filter type '%s' appears more than once; CreateGuardrail fails with \"Content policy must not include duplicate filters\"", [k]),
	"Keep one FiltersConfig entry per harmful category",
	"https://docs.aws.amazon.com/bedrock/latest/APIReference/API_GuardrailContentFilterConfig.html") if {
	some name in resources_of_type("AWS::Bedrock::Guardrail")
	xs := _pf_gcfu_items(name)
	some i, x in xs
	k := _pf_gcfu_key(x)
	some j, y in xs
	j < i
	_pf_gcfu_key(y) == k
}
