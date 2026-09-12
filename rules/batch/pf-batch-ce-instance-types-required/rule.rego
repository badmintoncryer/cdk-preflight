package cdk_preflight

import rego.v1

# Absent and [] are the same check; the empty list is the tighter fixture.
violation contains make_diag_full("pf-batch-ce-instance-types-required", "ERROR", name,
	"Properties.ComputeResources.InstanceTypes",
	sprintf("ComputeResources.Type %v lists no instance type (\"Resource instanceTypes are required.\"); an empty list counts as none", [t]),
	"List at least one instance type or family, or \"optimal\"",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_ComputeResource.html") if {
	some name in resources_of_type("AWS::Batch::ComputeEnvironment")
	_pf_batch_ce_ec2(name)
	t := _pf_batch_crtype(name)
	count(flatten_list(name, "Properties.ComputeResources.InstanceTypes")) == 0
}
