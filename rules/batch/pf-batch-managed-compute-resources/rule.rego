package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-managed-compute-resources", "ERROR", name,
	"Properties.ComputeResources",
	"Type MANAGED requires ComputeResources (\"computeResources must be provided for a MANAGED compute environment\")",
	"Add a ComputeResources block, or use Type UNMANAGED",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_CreateComputeEnvironment.html") if {
	some name in resources_of_type("AWS::Batch::ComputeEnvironment")
	resolve(name, "Properties.Type") == "MANAGED"
	props := input.resources[name].properties
	is_object(props)
	object.get(props, "ComputeResources", "__pf_absent") == "__pf_absent"
}
