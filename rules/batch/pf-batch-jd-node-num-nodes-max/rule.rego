package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jd-node-num-nodes-max", "ERROR", name,
	"Properties.NodeProperties.NumNodes",
	sprintf("NumNodes is %v (\"Number of nodes must be between 1 and 1000.\")", [n]),
	"Use between 1 and 1000 nodes",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_NodeProperties.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	n := _pf_batch_oget(_pf_batch_np(name), "NumNodes")
	is_number(n)
	_pf_batch_outside(n, 1, 1000)
}
