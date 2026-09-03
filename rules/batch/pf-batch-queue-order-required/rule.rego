package cdk_preflight

import rego.v1

# The schema accepts an empty list; the service rejects it. True
# absence is schema territory, so only the present-and-empty shape
# is claimed (input.resources sees the raw list).
violation contains make_diag_full("pf-batch-queue-order-required", "ERROR", name,
	"Properties.ComputeEnvironmentOrder",
	"ComputeEnvironmentOrder is empty (\"computeEnvironmentOrder is required.\")",
	"List at least one compute environment",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_CreateJobQueue.html") if {
	some name in resources_of_type("AWS::Batch::JobQueue")
	props := input.resources[name].properties
	is_object(props)
	order := object.get(props, "ComputeEnvironmentOrder", "__pf_absent")
	is_array(order)
	count(order) == 0
}
