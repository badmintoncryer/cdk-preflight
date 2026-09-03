package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-ce-vcpus-order", "ERROR", name,
	"Properties.ComputeResources.MaxvCpus",
	sprintf("MaxvCpus %v is below MinvCpus %v (\"maxvCpus should be greater than or equal to minvCpus.\")", [mx, mn]),
	"Keep MinvCpus <= MaxvCpus",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_CreateComputeEnvironment.html") if {
	some name in resources_of_type("AWS::Batch::ComputeEnvironment")
	mn := to_number(resolve(name, "Properties.ComputeResources.MinvCpus"))
	mx := to_number(resolve(name, "Properties.ComputeResources.MaxvCpus"))
	mx < mn
}
