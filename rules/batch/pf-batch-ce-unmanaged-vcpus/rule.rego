package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-ce-unmanaged-vcpus", "ERROR", name,
	"Properties.UnmanagedvCpus",
	sprintf("UnmanagedvCpus is set on a %v compute environment (\"unmanagedvCpus is not applicable for managed Compute Environments\")", [t]),
	"Drop UnmanagedvCpus, or set Type: UNMANAGED",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_CreateComputeEnvironment.html") if {
	some name in resources_of_type("AWS::Batch::ComputeEnvironment")
	_pf_batch_has(name, "UnmanagedvCpus")
	t := _pf_batch_get(name, "Type")
	_pf_batch_lit(t)
	t != "UNMANAGED"
}
