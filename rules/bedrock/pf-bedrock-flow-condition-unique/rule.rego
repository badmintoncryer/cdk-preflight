package cdk_preflight

import rego.v1

_pf_fcu_url := "https://docs.aws.amazon.com/bedrock/latest/APIReference/API_agent_FlowCondition.html"

_pf_fcu_conds(n) := cs if {
	n.Type == "Condition"
	cs := n.Configuration.Condition.Conditions
	is_array(cs)
}

violation contains make_diag_full("pf-bedrock-flow-condition-unique", "ERROR", name,
	sprintf("%s.Nodes[%d].Configuration.Condition.Conditions[%d].%s", [_pf_bedrocklib_flow_prop(name), i, j, field]),
	sprintf("Condition node '%s' repeats the %s '%s'; %s", [n.Name, lower(field), v, why[field]]),
	"Give every condition a distinct Name and a distinct Expression",
	_pf_fcu_url) if {
	some name in resources_of_type("AWS::Bedrock::Flow")
	some i, n in _pf_bedrocklib_flow_nodes(name)
	cs := _pf_fcu_conds(n)
	some field in ["Name", "Expression"]
	why := {"Name": "CreateFlow fails with \"Condition name … must be unique\"", "Expression": "PrepareFlow fails with \"has multiple conditions with the same expression\""}
	some j, c in cs
	v := object.get(c, field, null)
	is_string(v)
	some k, d in cs
	k < j
	object.get(d, field, null) == v
}
