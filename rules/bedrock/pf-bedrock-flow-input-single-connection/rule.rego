package cdk_preflight

import rego.v1

# PrepareFlow rejects a second connection into the same target input, which
# also covers duplicate connections (measured 2026-09-06).
violation contains make_diag_full("pf-bedrock-flow-input-single-connection", "ERROR", name,
	sprintf("%s.Connections[%d]", [_pf_bedrocklib_flow_prop(name), i]),
	sprintf("Connection '%s' is the second connection into input '%s' of node '%s'; PrepareFlow fails with \"has multiple incoming connections\"", [c.Name, ti, c.Target]),
	"Keep one incoming connection per node input",
	"https://docs.aws.amazon.com/bedrock/latest/APIReference/API_agent_FlowConnection.html") if {
	some name in resources_of_type("AWS::Bedrock::Flow")
	conns := _pf_bedrocklib_flow_conns(name)
	some i, c in conns
	c.Type == "Data"
	ti := c.Configuration.Data.TargetInput
	is_string(ti)
	some j, d in conns
	j < i
	d.Type == "Data"
	d.Target == c.Target
	d.Configuration.Data.TargetInput == ti
}
