package cdk_preflight

import rego.v1

_pf_gwdu_items(name) := xs if {
	p := _pf_bedrocklib_props(name)
	xs := object.get(object.get(p, "WordPolicyConfig", {}), "WordsConfig", [])
	is_array(xs)
}

_pf_gwdu_key(x) := lower(k) if {
	is_object(x)
	k := object.get(x, "Text", null)
	is_string(k)
}

violation contains make_diag_full("pf-bedrock-guardrail-word-unique", "ERROR", name,
	sprintf("Properties.WordPolicyConfig.WordsConfig[%d].Text", [i]),
	sprintf("Custom word '%s' appears more than once (case-insensitively); CreateGuardrail fails with \"Custom words cannot have case-insensitive duplicates\"", [k]),
	"List each custom word or phrase once",
	"https://docs.aws.amazon.com/bedrock/latest/APIReference/API_GuardrailWordConfig.html") if {
	some name in resources_of_type("AWS::Bedrock::Guardrail")
	xs := _pf_gwdu_items(name)
	some i, x in xs
	k := _pf_gwdu_key(x)
	some j, y in xs
	j < i
	_pf_gwdu_key(y) == k
}
