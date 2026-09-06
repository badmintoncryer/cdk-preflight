package cdk_preflight

import rego.v1

# The Input node's only output is `document`; PrepareFlow rejects any other
# output name on it (measured 2026-09-06).
violation contains make_diag_full("pf-bedrock-flow-input-node-output", "ERROR", name,
	sprintf("%s.Nodes[%d].Outputs[%d].Name", [_pf_bedrocklib_flow_prop(name), i, j]),
	sprintf("Input node '%s' declares output '%s'; PrepareFlow fails with \"has an unknown output '%s' that is not supported by this node type\"", [n.Name, o.Name, o.Name]),
	"Declare only Outputs: [{Name: document, Type: …}] on the Input node",
	"https://docs.aws.amazon.com/bedrock/latest/userguide/flows-nodes.html") if {
	some name in resources_of_type("AWS::Bedrock::Flow")
	some i, n in _pf_bedrocklib_flow_nodes(name)
	n.Type == "Input"
	some j, o in object.get(n, "Outputs", [])
	is_object(o)
	is_string(o.Name)
	o.Name != "document"
}
