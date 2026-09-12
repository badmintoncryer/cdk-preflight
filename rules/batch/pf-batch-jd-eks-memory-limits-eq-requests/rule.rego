package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jd-eks-memory-limits-eq-requests", "ERROR", name,
	"Properties.EksProperties.PodProperties.Containers",
	sprintf("the memory request is %v MiB and the limit %v MiB (\"memory request must be equal to memory limit if both are provided.\")", [r, l]),
	"Use the same memory value in Requests and Limits",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_EksContainerResourceRequirements.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	some c in _pf_batch_eks_containers(name)
	l := _pf_batch_eks_mib(_pf_batch_eks_resval(c.value, "Limits", "memory"))
	r := _pf_batch_eks_mib(_pf_batch_eks_resval(c.value, "Requests", "memory"))
	l != r
}
