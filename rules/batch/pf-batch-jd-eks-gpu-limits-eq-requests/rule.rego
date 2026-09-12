package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jd-eks-gpu-limits-eq-requests", "ERROR", name,
	"Properties.EksProperties.PodProperties.Containers",
	sprintf("the nvidia.com/gpu request is %v and the limit %v (\"gpu request must be equal to gpu limit if both are provided.\")", [r, l]),
	"Use the same nvidia.com/gpu value in Requests and Limits",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_EksContainerResourceRequirements.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	some c in _pf_batch_eks_containers(name)
	l := _pf_batch_eks_numval(c.value, "Limits", "nvidia.com/gpu")
	r := _pf_batch_eks_numval(c.value, "Requests", "nvidia.com/gpu")
	l != r
}
