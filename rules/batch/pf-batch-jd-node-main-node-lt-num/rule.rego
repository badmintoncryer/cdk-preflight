package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jd-node-main-node-lt-num", "ERROR", name,
	"Properties.NodeProperties.MainNode",
	sprintf("MainNode is %v but the job has %v nodes (\"Main node index is out of range, must be less than numNodes.\")", [m, n]),
	"Use a MainNode index below NumNodes",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_NodeProperties.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	p := _pf_batch_np(name)
	m := _pf_batch_oget(p, "MainNode")
	is_number(m)
	n := _pf_batch_oget(p, "NumNodes")
	is_number(n)
	m >= n
}
