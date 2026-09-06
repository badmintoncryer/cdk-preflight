package cdk_preflight

import rego.v1

# PrepareFlow (run by the CloudFormation handler) rejects connections whose
# Source or Target names no node (measured 2026-09-06).
violation contains make_diag_full("pf-bedrock-flow-connection-nodes", "ERROR", name,
	sprintf("%s.Connections[%d].%s", [_pf_bedrocklib_flow_prop(name), i, end]),
	sprintf("Connection '%s' names %s node '%s', which is not defined; PrepareFlow fails with \"references an unknown %s node\"", [c.Name, lower(end), nn, lower(end)]),
	"Point Source / Target at the Name of a node in the same definition",
	"https://docs.aws.amazon.com/bedrock/latest/APIReference/API_agent_FlowConnection.html") if {
	some name in resources_of_type("AWS::Bedrock::Flow")
	names := _pf_bedrocklib_flow_node_names(name)
	some i, c in _pf_bedrocklib_flow_conns(name)
	some end in ["Source", "Target"]
	nn := c[end]
	is_string(nn)
	not names[nn]
}
