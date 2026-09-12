package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jd-eks-resource-key-unsupported", "ERROR", name,
	"Properties.EksProperties.PodProperties.Containers",
	sprintf("%v is not a supported resource type (\"%v is not a supported type for resources.\")", [k, k]),
	"Request only cpu, memory and nvidia.com/gpu",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_EksContainerResourceRequirements.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	some c in _pf_batch_eks_containers(name)
	bad := [k | some k in _pf_batch_eks_reskeys(c.value); not k in {"cpu", "memory", "nvidia.com/gpu"}]
	count(bad) > 0
	k := bad[0]
}
