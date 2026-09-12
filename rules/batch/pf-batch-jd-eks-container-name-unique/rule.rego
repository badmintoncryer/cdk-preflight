package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jd-eks-container-name-unique", "ERROR", name,
	"Properties.EksProperties.PodProperties.Containers",
	sprintf("the container name %v is used %v times (\"The container name: %v must be unique in multi-container job.\")", [n, k, n]),
	"Give every container in the pod its own name",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_EksContainer.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	cs := _pf_batch_eks_containers(name)
	some c in cs
	n := _pf_batch_oget(c.value, "Name")
	_pf_batch_lit(n)
	k := count([1 | some x in cs; object.get(x.value, "Name", null) == n])
	k > 1
}
