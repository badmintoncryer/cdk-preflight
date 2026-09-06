package cdk_preflight

import rego.v1

# PrepareFlow resolves Configuration.Conditional.Condition against the source
# node's conditions; a non-Condition source has none (measured 2026-09-06).
# The engine's preprocessor treats the {"Condition": <name>} object as a
# template condition reference and replaces it with {"__dynamic": "condition
# reference: <name>"}, so both shapes are read.
_pf_fcc_cond(c) := v if {
	v := c.Configuration.Conditional.Condition
	is_string(v)
}

_pf_fcc_cond(c) := v if {
	d := c.Configuration.Conditional
	is_object(d)
	t := object.get(d, "__dynamic", null)
	is_string(t)
	startswith(t, "condition reference: ")
	v := substring(t, count("condition reference: "), -1)
}

violation contains make_diag_full("pf-bedrock-flow-connection-condition", "ERROR", name,
	sprintf("%s.Connections[%d].Configuration.Conditional.Condition", [_pf_bedrocklib_flow_prop(name), i]),
	sprintf("Conditional connection '%s' names condition '%s', which node '%s' does not define; PrepareFlow fails with \"references an unknown condition\"", [c.Name, cond, c.Source]),
	"Start Conditional connections at a Condition node and name one of its Conditions[].Name",
	"https://docs.aws.amazon.com/bedrock/latest/APIReference/API_agent_FlowConditionalConnectionConfiguration.html") if {
	some name in resources_of_type("AWS::Bedrock::Flow")
	some i, c in _pf_bedrocklib_flow_conns(name)
	c.Type == "Conditional"
	cond := _pf_fcc_cond(c)
	some src in _pf_bedrocklib_flow_nodes(name)
	src.Name == c.Source
	not _pf_bedrocklib_node_conditions(src)[cond]
}
