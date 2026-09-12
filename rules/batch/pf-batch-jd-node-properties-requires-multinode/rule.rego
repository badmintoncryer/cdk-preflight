package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jd-node-properties-requires-multinode", "ERROR", name,
	"Properties.NodeProperties",
	sprintf("NodeProperties is set on a job definition of type %v", [t]),
	"Set Type: multinode, or drop NodeProperties",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_RegisterJobDefinition.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	_pf_batch_has(name, "NodeProperties")
	t := _pf_batch_get(name, "Type")
	_pf_batch_lit(t)
	t != "multinode"
}
