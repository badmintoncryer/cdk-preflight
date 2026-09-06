package cdk_preflight

import rego.v1

_pf_pvnu_items(name) := xs if {
	p := _pf_bedrocklib_props(name)
	xs := object.get(p, "Variants", [])
	is_array(xs)
}

_pf_pvnu_key(x) := k if {
	is_object(x)
	k := object.get(x, "Name", null)
	is_string(k)
}

violation contains make_diag_full("pf-bedrock-prompt-variant-name-unique", "ERROR", name,
	sprintf("Properties.Variants[%d].Name", [i]),
	sprintf("Variant name '%s' is used more than once; CreatePrompt fails with \"All variant names in the prompt must be unique\"", [k]),
	"Give every Variants entry a distinct Name",
	"https://docs.aws.amazon.com/bedrock/latest/APIReference/API_agent_PromptVariant.html") if {
	some name in resources_of_type("AWS::Bedrock::Prompt")
	xs := _pf_pvnu_items(name)
	some i, x in xs
	k := _pf_pvnu_key(x)
	some j, y in xs
	j < i
	_pf_pvnu_key(y) == k
}
