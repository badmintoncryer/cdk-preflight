package cdk_preflight

import rego.v1

# Which keys the container sets, by presence: a number (cpu: 8) is a value even though the
# string helpers do not read it, and a key built with an intrinsic is there all the same.
_pf_bjer_keys(c) := ks if ks := _pf_batch_eks_reskeys(c)

_pf_bjer_keys(c) := set() if not _pf_batch_oget(c, "Resources")

violation contains make_diag_full("pf-batch-jd-eks-resources-required", "ERROR", name,
	"Properties.EksProperties.PodProperties.Containers",
	sprintf("the container %v sets neither Limits nor Requests for %v", [n, k]),
	"Set cpu and memory in Resources.Limits or Resources.Requests",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_EksContainerResourceRequirements.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	some c in _pf_batch_eks_containers(name)
	ks := _pf_bjer_keys(c.value)
	missing := [k | some k in ["cpu", "memory"]; not k in ks]
	count(missing) > 0
	k := missing[0]
	n := object.get(c.value, "Name", "(unnamed)")
}
