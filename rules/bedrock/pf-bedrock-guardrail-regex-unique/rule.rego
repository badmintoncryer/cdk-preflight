package cdk_preflight

import rego.v1

# CreateGuardrail requires both the names and the patterns of the regex
# filters to be unique (measured 2026-09-06); the schema has no uniqueItems.
_pf_grxu_items(name) := xs if {
	p := _pf_bedrocklib_props(name)
	xs := object.get(object.get(p, "SensitiveInformationPolicyConfig", {}), "RegexesConfig", [])
	is_array(xs)
}

_pf_grxu_dup(name, field) := [i, v] if {
	xs := _pf_grxu_items(name)
	some i, x in xs
	is_object(x)
	v := object.get(x, field, null)
	is_string(v)
	some j, y in xs
	j < i
	object.get(y, field, null) == v
}

violation contains make_diag_full("pf-bedrock-guardrail-regex-unique", "ERROR", name,
	sprintf("Properties.SensitiveInformationPolicyConfig.RegexesConfig[%d].%s", [d[0], field]),
	sprintf("Regex filter %s '%s' is used more than once; CreateGuardrail fails with \"All regex %ss must be unique\"", [lower(field), d[1], lower(field)]),
	"Give every RegexesConfig entry a distinct Name and a distinct Pattern",
	"https://docs.aws.amazon.com/bedrock/latest/APIReference/API_GuardrailRegexConfig.html") if {
	some name in resources_of_type("AWS::Bedrock::Guardrail")
	some field in ["Name", "Pattern"]
	d := _pf_grxu_dup(name, field)
}
