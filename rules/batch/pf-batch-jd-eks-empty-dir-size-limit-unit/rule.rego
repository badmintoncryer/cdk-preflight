package cdk_preflight

import rego.v1

# Found while benching the volume fixtures: a SizeLimit of 1Gi is rejected
# and 100Mi is accepted, the same MiB-only rule the container resources use.
violation contains make_diag_full("pf-batch-jd-eks-empty-dir-size-limit-unit", "ERROR", name,
	"Properties.EksProperties.PodProperties.Volumes",
	sprintf("the empty directory size limit %v does not use the Mi unit (\"Invalid empty dir size limit.\")", [v]),
	"Express the size limit in MiB, for example 100Mi",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_EksEmptyDir.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	some vol in flatten_list(name, "Properties.EksProperties.PodProperties.Volumes")
	v := _pf_batch_oget(_pf_batch_oget(vol.value, "EmptyDir"), "SizeLimit")
	_pf_batch_lit(v)
	_pf_batch_eks_mem_bad(v)
}
