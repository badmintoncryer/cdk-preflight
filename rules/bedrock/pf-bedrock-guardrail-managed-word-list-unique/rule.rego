package cdk_preflight

import rego.v1

_pf_gmwu_items(name) := xs if {
	p := _pf_bedrocklib_props(name)
	xs := object.get(object.get(p, "WordPolicyConfig", {}), "ManagedWordListsConfig", [])
	is_array(xs)
}

_pf_gmwu_key(x) := k if {
	is_object(x)
	k := object.get(x, "Type", null)
	is_string(k)
}

violation contains make_diag_full("pf-bedrock-guardrail-managed-word-list-unique", "ERROR", name,
	sprintf("Properties.WordPolicyConfig.ManagedWordListsConfig[%d].Type", [i]),
	sprintf("Managed word list '%s' appears more than once; CreateGuardrail fails with \"Managed words cannot have duplicates\"", [k]),
	"Keep one ManagedWordListsConfig entry per list type",
	"https://docs.aws.amazon.com/bedrock/latest/APIReference/API_GuardrailManagedWordsConfig.html") if {
	some name in resources_of_type("AWS::Bedrock::Guardrail")
	xs := _pf_gmwu_items(name)
	some i, x in xs
	k := _pf_gmwu_key(x)
	some j, y in xs
	j < i
	_pf_gmwu_key(y) == k
}
