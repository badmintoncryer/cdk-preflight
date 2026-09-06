package cdk_preflight

import rego.v1

# FlowNodeConfiguration is a union keyed exactly like the node Type
# (Input, Output, Prompt, …); the schema's oneOf only guarantees one member.
# A mismatch fails CreateFlow, an absent block fails PrepareFlow (measured
# 2026-09-06).
_pf_fnc_url := "https://docs.aws.amazon.com/bedrock/latest/APIReference/API_agent_FlowNode.html"

violation contains make_diag_full("pf-bedrock-flow-node-configuration", "ERROR", name,
	sprintf("%s.Nodes[%d].Configuration", [_pf_bedrocklib_flow_prop(name), i]),
	sprintf("Node '%s' of Type %s has no Configuration; PrepareFlow fails with \"is missing its required configuration\"", [n.Name, t]),
	sprintf("Add Configuration.%s to the node", [t]),
	_pf_fnc_url) if {
	some name in resources_of_type("AWS::Bedrock::Flow")
	some i, n in _pf_bedrocklib_flow_nodes(name)
	t := n.Type
	is_string(t)
	not _pf_bedrocklib_has(n, "Configuration")
}

violation contains make_diag_full("pf-bedrock-flow-node-configuration", "ERROR", name,
	sprintf("%s.Nodes[%d].Configuration", [_pf_bedrocklib_flow_prop(name), i]),
	sprintf("Node '%s' of Type %s carries Configuration.%v instead of Configuration.%s; CreateFlow fails with \"Configuration must be provided for node %s\"", [n.Name, t, keys, t, n.Name]),
	sprintf("Use the Configuration.%s member", [t]),
	_pf_fnc_url) if {
	some name in resources_of_type("AWS::Bedrock::Flow")
	some i, n in _pf_bedrocklib_flow_nodes(name)
	t := n.Type
	is_string(t)
	cfg := n.Configuration
	is_object(cfg)
	keys := object.keys(cfg)
	count(keys) > 0
	not _pf_bedrocklib_has(cfg, t)
}
