package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-ce-eks-allocation-strategy", "ERROR", name,
	"Properties.ComputeResources.AllocationStrategy",
	"an EKS compute environment without AllocationStrategy (\"allocationStrategy is required for EKS Compute Environments.\")",
	"Set AllocationStrategy, for example BEST_FIT_PROGRESSIVE",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_ComputeResource.html") if {
	some name in resources_of_type("AWS::Batch::ComputeEnvironment")
	_pf_batch_ce_eks(name)
	_pf_batch_ce_ec2(name)
	not _pf_batch_crhas(name, "AllocationStrategy")
}
