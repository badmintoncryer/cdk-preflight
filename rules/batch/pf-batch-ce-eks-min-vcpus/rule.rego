package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-ce-eks-min-vcpus", "ERROR", name,
	"Properties.ComputeResources.MinvCpus",
	"an EKS compute environment without MinvCpus (\"Resource minvCpus is required.\")",
	"Set MinvCpus, 0 to keep the environment idle",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_ComputeResource.html") if {
	some name in resources_of_type("AWS::Batch::ComputeEnvironment")
	_pf_batch_ce_eks(name)
	_pf_batch_ce_ec2(name)
	not _pf_batch_crhas(name, "MinvCpus")
}
