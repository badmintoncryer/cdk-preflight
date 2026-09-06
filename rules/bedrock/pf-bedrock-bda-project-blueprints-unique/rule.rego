package cdk_preflight

import rego.v1

# Compared as literal ARNs or as the same in-template Blueprint (Ref / GetAtt).
_pf_bbu_key(v) := v if is_string(v)

_pf_bbu_key(v) := k if {
	is_object(v)
	ref := object.get(v, "__ref", null)
	is_string(ref)
	k := sprintf("ref:%s", [ref])
}

violation contains make_diag_full("pf-bedrock-bda-project-blueprints-unique", "ERROR", name,
	sprintf("Properties.CustomOutputConfiguration.Blueprints[%d].BlueprintArn", [i]),
	"The same blueprint is attached more than once; CreateDataAutomationProject fails with \"Cannot contain more than 1 version of 1 Blueprint or duplicate Blueprints\"",
	"Attach each blueprint once",
	"https://docs.aws.amazon.com/bedrock/latest/APIReference/API_data-automation_CreateDataAutomationProject.html") if {
	some name in resources_of_type("AWS::Bedrock::DataAutomationProject")
	bps := object.get(object.get(_pf_bedrocklib_props(name), "CustomOutputConfiguration", {}), "Blueprints", [])
	some i, b in bps
	is_object(b)
	k := _pf_bbu_key(object.get(b, "BlueprintArn", null))
	some j, c in bps
	j < i
	is_object(c)
	_pf_bbu_key(object.get(c, "BlueprintArn", null)) == k
}
