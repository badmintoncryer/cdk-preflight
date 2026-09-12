package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jd-eks-containers-required", "ERROR", name,
	"Properties.EksProperties.PodProperties.Containers",
	"the pod declares no containers (\"Containers must be provided for Batch on EKS jobs.\")",
	"Declare a container in PodProperties.Containers",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_EksPodProperties.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	_pf_batch_pod(name)
	count(_pf_batch_eks_containers(name)) == 0
}
