package cdk_preflight

import rego.v1

# PrepareFlow requires every Condition node to carry a condition named
# "default" (measured 2026-09-06).
violation contains make_diag_full("pf-bedrock-flow-condition-default", "ERROR", name,
	sprintf("%s.Nodes[%d].Configuration.Condition.Conditions", [_pf_bedrocklib_flow_prop(name), i]),
	sprintf("Condition node '%s' has no condition named 'default'; PrepareFlow fails with \"is missing a default condition\"", [n.Name]),
	"Add {Name: default} (no Expression) as the last condition and connect it",
	"https://docs.aws.amazon.com/bedrock/latest/userguide/flows-nodes.html") if {
	some name in resources_of_type("AWS::Bedrock::Flow")
	some i, n in _pf_bedrocklib_flow_nodes(name)
	n.Type == "Condition"
	is_object(n.Configuration)
	not _pf_bedrocklib_node_conditions(n)["default"]
}
