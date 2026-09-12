package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jd-node-ranges-max", "ERROR", name,
	"Properties.NodeProperties.NodeRangeProperties",
	sprintf("the job definition declares %v node ranges (\"Maximum allowed size of node range properties is 5\")", [c]),
	"Use at most 5 node ranges",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_NodeProperties.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	c := count(_pf_batch_ranges(name))
	c > 5
}
