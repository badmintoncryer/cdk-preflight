package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jd-eks-cpu-limits-ge-requests", "ERROR", name,
	"Properties.EksProperties.PodProperties.Containers",
	sprintf("the cpu request is %v and the limit %v (\"cpu request must be <= to cpu limit if both are provided.\")", [r, l]),
	"Lower the cpu request to at most the cpu limit",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_EksContainerResourceRequirements.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	some c in _pf_batch_eks_containers(name)
	l := _pf_batch_eks_numval(c.value, "Limits", "cpu")
	r := _pf_batch_eks_numval(c.value, "Requests", "cpu")
	r > l
}
