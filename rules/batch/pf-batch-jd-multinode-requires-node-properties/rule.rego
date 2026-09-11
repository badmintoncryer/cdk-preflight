package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jd-multinode-requires-node-properties", "ERROR", name,
	"Properties.NodeProperties",
	"Type is multinode but NodeProperties is missing (\"Node properties of multinode job is required.\")",
	"Add NodeProperties, or use Type: container",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_RegisterJobDefinition.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	_pf_batch_get(name, "Type") == "multinode"
	not _pf_batch_has(name, "NodeProperties")
}
