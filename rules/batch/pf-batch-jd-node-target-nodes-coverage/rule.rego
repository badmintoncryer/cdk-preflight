package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jd-node-target-nodes-coverage", "ERROR", name,
	"Properties.NodeProperties.NodeRangeProperties",
	sprintf("the node ranges cover %v of the %v nodes", [c, n]),
	"Extend the node ranges to cover 0 through NumNodes-1",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_NodeRangeProperty.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	n := _pf_batch_oget(_pf_batch_np(name), "NumNodes")
	is_number(n)
	count(_pf_batch_target_nodes(name)) == count(_pf_batch_ranges(name))
	c := count(_pf_batch_covered(name, n))
	c < n
}
