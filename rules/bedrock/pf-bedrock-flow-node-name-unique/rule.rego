package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-bedrock-flow-node-name-unique", "ERROR", name,
	sprintf("%s.Nodes[%d].Name", [_pf_bedrocklib_flow_prop(name), i]),
	sprintf("Node name '%s' is used more than once; CreateFlow fails with \"Node name %s must be unique\"", [nn, nn]),
	"Give every node a distinct Name",
	"https://docs.aws.amazon.com/bedrock/latest/APIReference/API_agent_FlowNode.html") if {
	some name in resources_of_type("AWS::Bedrock::Flow")
	nodes := _pf_bedrocklib_flow_nodes(name)
	some i, x in nodes
	nn := x.Name
	is_string(nn)
	some j, y in nodes
	j < i
	y.Name == nn
}
