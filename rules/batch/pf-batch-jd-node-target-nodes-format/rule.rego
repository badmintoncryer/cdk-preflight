package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jd-node-target-nodes-format", "ERROR", name,
	"Properties.NodeProperties.NodeRangeProperties",
	sprintf("TargetNodes %v is not a node index or range (\"targetNodes should contain only digits.\")", [t]),
	"Write the range as 0:1, 0: or 0",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_NodeRangeProperty.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	some r in _pf_batch_ranges(name)
	t := _pf_batch_oget(r.value, "TargetNodes")
	_pf_batch_lit(t)
	not regex.match(`^[0-9]*(:[0-9]*)?$`, t)
}
