package cdk_preflight

import rego.v1

_pf_gpiu_items(name) := xs if {
	p := _pf_bedrocklib_props(name)
	xs := object.get(object.get(p, "SensitiveInformationPolicyConfig", {}), "PiiEntitiesConfig", [])
	is_array(xs)
}

_pf_gpiu_key(x) := k if {
	is_object(x)
	k := object.get(x, "Type", null)
	is_string(k)
}

violation contains make_diag_full("pf-bedrock-guardrail-pii-entity-unique", "ERROR", name,
	sprintf("Properties.SensitiveInformationPolicyConfig.PiiEntitiesConfig[%d].Type", [i]),
	sprintf("PII entity type '%s' appears more than once; CreateGuardrail fails with \"The PII entity configs cannot have duplicates\"", [k]),
	"Keep one PiiEntitiesConfig entry per entity type",
	"https://docs.aws.amazon.com/bedrock/latest/APIReference/API_GuardrailPiiEntityConfig.html") if {
	some name in resources_of_type("AWS::Bedrock::Guardrail")
	xs := _pf_gpiu_items(name)
	some i, x in xs
	k := _pf_gpiu_key(x)
	some j, y in xs
	j < i
	_pf_gpiu_key(y) == k
}
