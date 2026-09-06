package cdk_preflight

import rego.v1

_pf_gtnu_items(name) := xs if {
	p := _pf_bedrocklib_props(name)
	xs := object.get(object.get(p, "TopicPolicyConfig", {}), "TopicsConfig", [])
	is_array(xs)
}

_pf_gtnu_key(x) := k if {
	is_object(x)
	k := object.get(x, "Name", null)
	is_string(k)
}

violation contains make_diag_full("pf-bedrock-guardrail-topic-name-unique", "ERROR", name,
	sprintf("Properties.TopicPolicyConfig.TopicsConfig[%d].Name", [i]),
	sprintf("Denied topic name '%s' is used more than once; CreateGuardrail fails with \"Topic policy topic names are not unique\"", [k]),
	"Give every TopicsConfig entry a distinct Name",
	"https://docs.aws.amazon.com/bedrock/latest/APIReference/API_GuardrailTopicConfig.html") if {
	some name in resources_of_type("AWS::Bedrock::Guardrail")
	xs := _pf_gtnu_items(name)
	some i, x in xs
	k := _pf_gtnu_key(x)
	some j, y in xs
	j < i
	_pf_gtnu_key(y) == k
}
