package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jd-node-range-payload-exclusive", "ERROR", name,
	"Properties.NodeProperties.NodeRangeProperties",
	sprintf("node range %v sets %v of Container, EcsProperties and EksProperties (\"NodeRangeProperties can not use both ecsProperties and container fields\")", [t, c]),
	"Keep one of Container, EcsProperties or EksProperties per node range",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_NodeRangeProperty.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	some r in _pf_batch_ranges(name)
	c := count(_pf_batch_range_payloads(r.value))
	c > 1
	t := object.get(r.value, "TargetNodes", "(unset)")
}
