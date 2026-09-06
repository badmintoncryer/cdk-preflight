package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-bedrock-flow-connection-name-unique", "ERROR", name,
	sprintf("%s.Connections[%d].Name", [_pf_bedrocklib_flow_prop(name), i]),
	sprintf("Connection name '%s' is used more than once; CreateFlow fails with \"Connection name %s must be unique\"", [cn, cn]),
	"Give every connection a distinct Name",
	"https://docs.aws.amazon.com/bedrock/latest/APIReference/API_agent_FlowConnection.html") if {
	some name in resources_of_type("AWS::Bedrock::Flow")
	conns := _pf_bedrocklib_flow_conns(name)
	some i, x in conns
	cn := x.Name
	is_string(cn)
	some j, y in conns
	j < i
	y.Name == cn
}
