package cdk_preflight

import rego.v1

_pf_arnu_url := "https://docs.aws.amazon.com/bedrock/latest/APIReference/API_AutomatedReasoningPolicyDefinition.html"

_pf_arnu_def(name) := pd if {
	pd := object.get(_pf_bedrocklib_props(name), "PolicyDefinition", null)
	is_object(pd)
}

# [list key, field, message]
_pf_arnu_lists := [["Types", "Name", "Duplicate name found in policy definition"], ["Variables", "Name", "Duplicate name found in policy definition"], ["Rules", "Id", "Duplicate id found in policy definition"]]

violation contains make_diag_full("pf-bedrock-automated-reasoning-policy-names-unique", "ERROR", name,
	sprintf("Properties.PolicyDefinition.%s[%d].%s", [l[0], i, l[1]]),
	sprintf("%s entry '%s' is declared more than once; CreateAutomatedReasoningPolicy fails with \"%s\"", [l[0], v, l[2]]),
	"Use distinct names for types and variables and distinct ids for rules",
	_pf_arnu_url) if {
	some name in resources_of_type("AWS::Bedrock::AutomatedReasoningPolicy")
	pd := _pf_arnu_def(name)
	some l in _pf_arnu_lists
	xs := object.get(pd, l[0], [])
	some i, x in xs
	is_object(x)
	v := object.get(x, l[1], null)
	is_string(v)
	some j, y in xs
	j < i
	object.get(y, l[1], null) == v
}

violation contains make_diag_full("pf-bedrock-automated-reasoning-policy-names-unique", "ERROR", name,
	sprintf("Properties.PolicyDefinition.Types[%d].Values[%d].Value", [i, j]),
	sprintf("Type '%s' lists value '%s' more than once; CreateAutomatedReasoningPolicy fails with \"Type … has duplicate values\"", [t.Name, v]),
	"List each value of a type once",
	_pf_arnu_url) if {
	some name in resources_of_type("AWS::Bedrock::AutomatedReasoningPolicy")
	pd := _pf_arnu_def(name)
	some i, t in object.get(pd, "Types", [])
	is_object(t)
	vs := object.get(t, "Values", [])
	some j, x in vs
	is_object(x)
	v := x.Value
	is_string(v)
	some k, y in vs
	k < j
	object.get(y, "Value", null) == v
}
