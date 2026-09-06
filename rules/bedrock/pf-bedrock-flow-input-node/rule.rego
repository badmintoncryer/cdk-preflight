package cdk_preflight

import rego.v1

# The CloudFormation handler prepares the flow after creating it and fails the
# resource on validation errors (measured 2026-09-06); a missing Input node is
# one of them, a second Input node is refused by CreateFlow itself.
violation contains make_diag_full("pf-bedrock-flow-input-node", "ERROR", name,
	_pf_bedrocklib_flow_prop(name),
	sprintf("The flow defines %d Input nodes; it needs exactly one (PrepareFlow: \"The flow is missing a required Flow Input node\" / CreateFlow: \"max-number-flow-input-nodes is 1\")", [n]),
	"Define exactly one node of Type Input",
	"https://docs.aws.amazon.com/bedrock/latest/userguide/flows-nodes.html") if {
	some name in resources_of_type("AWS::Bedrock::Flow")
	nodes := _pf_bedrocklib_flow_nodes(name)
	n := count([x | some x in nodes; x.Type == "Input"])
	n != 1
}
