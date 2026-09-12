package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jd-eks-resources-required", "ERROR", name,
	"Properties.EksProperties.PodProperties.Containers",
	sprintf("the container %v sets neither Limits nor Requests for %v", [n, k]),
	"Set cpu and memory in Resources.Limits or Resources.Requests",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_EksContainerResourceRequirements.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	some c in _pf_batch_eks_containers(name)
	missing := [k | some k in ["cpu", "memory"]; count(_pf_batch_eks_vals(c.value, k)) == 0]
	count(missing) > 0
	k := missing[0]
	n := object.get(c.value, "Name", "(unnamed)")
}
