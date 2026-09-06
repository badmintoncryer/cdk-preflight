package cdk_preflight

import rego.v1

_pf_rmu_items(name) := xs if {
	p := _pf_bedrocklib_props(name)
	xs := object.get(p, "Models", [])
	is_array(xs)
}

_pf_rmu_key(x) := k if {
	is_object(x)
	k := object.get(x, "ModelArn", null)
	is_string(k)
}

violation contains make_diag_full("pf-bedrock-prompt-router-models-unique", "ERROR", name,
	sprintf("Properties.Models[%d].ModelArn", [i]),
	sprintf("Model '%s' is listed more than once; CreatePromptRouter fails with \"Duplicate foundation models have been identified in the list of models\"", [k]),
	"List two different models",
	"https://docs.aws.amazon.com/bedrock/latest/APIReference/API_CreatePromptRouter.html") if {
	some name in resources_of_type("AWS::Bedrock::IntelligentPromptRouter")
	xs := _pf_rmu_items(name)
	some i, x in xs
	k := _pf_rmu_key(x)
	some j, y in xs
	j < i
	_pf_rmu_key(y) == k
}
