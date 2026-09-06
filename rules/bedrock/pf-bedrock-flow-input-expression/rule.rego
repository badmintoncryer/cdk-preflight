package cdk_preflight

import rego.v1

# Input expressions address the incoming payload as $.data[...]; PrepareFlow
# rejects anything else (measured 2026-09-06). The schema only bounds the length.
violation contains make_diag_full("pf-bedrock-flow-input-expression", "ERROR", name,
	sprintf("%s.Nodes[%d].Inputs[%d].Expression", [_pf_bedrocklib_flow_prop(name), i, j]),
	sprintf("Input '%s' of node '%s' has expression '%s'; PrepareFlow fails with \"Expression must start with $.data\"", [inp.Name, n.Name, e]),
	"Use $.data for the whole payload or $.data.<key> / $.data[<index>] for a part of it",
	"https://docs.aws.amazon.com/bedrock/latest/userguide/flows-expressions.html") if {
	some name in resources_of_type("AWS::Bedrock::Flow")
	some i, n in _pf_bedrocklib_flow_nodes(name)
	some j, inp in object.get(n, "Inputs", [])
	is_object(inp)
	e := inp.Expression
	is_string(e)
	not regex.match(`^\$\.data($|[.\[])`, e)
}
