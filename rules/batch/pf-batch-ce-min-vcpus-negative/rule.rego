package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-ce-min-vcpus-negative", "ERROR", name,
	"Properties.ComputeResources.MinvCpus",
	sprintf("MinvCpus is %v (\"minvCpus should be greater than or equal to 0.\")", [mn]),
	"Use 0 or more vCPUs as the floor",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_ComputeResource.html") if {
	some name in resources_of_type("AWS::Batch::ComputeEnvironment")
	mn := _pf_batch_crget(name, "MinvCpus")
	is_number(mn)
	mn < 0
}
