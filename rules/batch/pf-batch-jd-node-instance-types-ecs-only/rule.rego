package cdk_preflight

import rego.v1

# The user guide says every node range has to use the same instance type;
# the service instead rejects InstanceTypes outright unless the range carries
# ecsProperties, which is what this checks.
violation contains make_diag_full("pf-batch-jd-node-instance-types-ecs-only", "ERROR", name,
	"Properties.NodeProperties.NodeRangeProperties",
	sprintf("node range %v sets InstanceTypes without EcsProperties (\"Using instanceTypes with nodeRangeProperty is only allowed for ecsProperties jobs.\")", [t]),
	"Move the node range to EcsProperties, or drop InstanceTypes",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_NodeRangeProperty.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	some r in _pf_batch_ranges(name)
	_pf_batch_ohas(r.value, "InstanceTypes")
	not _pf_batch_ohas(r.value, "EcsProperties")
	t := object.get(r.value, "TargetNodes", "(unset)")
}
