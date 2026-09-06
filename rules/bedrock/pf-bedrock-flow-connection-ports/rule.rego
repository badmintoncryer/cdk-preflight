package cdk_preflight

import rego.v1

# PrepareFlow checks that a Data connection's SourceOutput is declared on the
# source node and TargetInput on the target node (measured 2026-09-06).
_pf_fcp_url := "https://docs.aws.amazon.com/bedrock/latest/APIReference/API_agent_FlowDataConnectionConfiguration.html"

_pf_fcp_node(name, nn) := n if {
	some n in _pf_bedrocklib_flow_nodes(name)
	n.Name == nn
	count([x | some x in _pf_bedrocklib_flow_nodes(name); x.Name == nn]) == 1
}

violation contains make_diag_full("pf-bedrock-flow-connection-ports", "ERROR", name,
	sprintf("%s.Connections[%d].Configuration.Data.SourceOutput", [_pf_bedrocklib_flow_prop(name), i]),
	sprintf("Connection '%s' reads output '%s' which node '%s' does not declare; PrepareFlow fails with \"references an unknown source output\"", [c.Name, so, c.Source]),
	"Use one of the source node's Outputs[].Name",
	_pf_fcp_url) if {
	some name in resources_of_type("AWS::Bedrock::Flow")
	some i, c in _pf_bedrocklib_flow_conns(name)
	c.Type == "Data"
	so := c.Configuration.Data.SourceOutput
	is_string(so)
	src := _pf_fcp_node(name, c.Source)
	not _pf_bedrocklib_node_outputs(src)[so]
}

violation contains make_diag_full("pf-bedrock-flow-connection-ports", "ERROR", name,
	sprintf("%s.Connections[%d].Configuration.Data.TargetInput", [_pf_bedrocklib_flow_prop(name), i]),
	sprintf("Connection '%s' feeds input '%s' which node '%s' does not declare; PrepareFlow fails with \"references an unknown target input\"", [c.Name, ti, c.Target]),
	"Use one of the target node's Inputs[].Name",
	_pf_fcp_url) if {
	some name in resources_of_type("AWS::Bedrock::Flow")
	some i, c in _pf_bedrocklib_flow_conns(name)
	c.Type == "Data"
	ti := c.Configuration.Data.TargetInput
	is_string(ti)
	tgt := _pf_fcp_node(name, c.Target)
	not _pf_bedrocklib_node_inputs(tgt)[ti]
}
