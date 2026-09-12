package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jd-node-target-nodes-in-range", "ERROR", name,
	"Properties.NodeProperties.NodeRangeProperties",
	sprintf("TargetNodes %v addresses a node index outside the %v nodes of the job", [t, n]),
	"Keep every node index below NumNodes",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_NodeRangeProperty.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	n := _pf_batch_oget(_pf_batch_np(name), "NumNodes")
	is_number(n)
	bad := [t | some t in _pf_batch_target_nodes(name); max(_pf_batch_target(t, n)) >= n]
	count(bad) > 0
	t := bad[0]
}
