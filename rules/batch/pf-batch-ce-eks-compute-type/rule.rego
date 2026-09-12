package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-ce-eks-compute-type", "ERROR", name,
	"Properties.ComputeResources.Type",
	sprintf("an EKS compute environment uses ComputeResources.Type %v (\"Supported compute types for EKS compute environments are [EC2, SPOT]\")", [t]),
	"Use EC2 or SPOT compute resources, or drop EksConfiguration",
	"https://docs.aws.amazon.com/batch/latest/userguide/fargate.html") if {
	some name in resources_of_type("AWS::Batch::ComputeEnvironment")
	_pf_batch_ce_eks(name)
	t := _pf_batch_crtype(name)
	_pf_batch_ce_fargate(name)
}
