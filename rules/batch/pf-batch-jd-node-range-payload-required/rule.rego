package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jd-node-range-payload-required", "ERROR", name,
	"Properties.NodeProperties.NodeRangeProperties",
	sprintf("node range %v defines none of Container, EcsProperties and EksProperties (\"Must specify container for node range %v\")", [t, t]),
	"Give the node range a container",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_NodeRangeProperty.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	some r in _pf_batch_ranges(name)
	count(_pf_batch_range_payloads(r.value)) == 0
	t := object.get(r.value, "TargetNodes", "(unset)")
}
