package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jd-eks-memory-unit", "ERROR", name,
	"Properties.EksProperties.PodProperties.Containers",
	sprintf("the memory value %v does not use the Mi unit (\"Value %v for type memory is not valid.\")", [v, v]),
	"Express memory in MiB, for example 2048Mi",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_EksContainerResourceRequirements.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	some c in _pf_batch_eks_containers(name)
	bad := [v | some v in _pf_batch_eks_vals(c.value, "memory"); _pf_batch_eks_mem_bad(v)]
	count(bad) > 0
	v := bad[0]
}
