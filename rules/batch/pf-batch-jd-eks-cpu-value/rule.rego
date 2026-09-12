package cdk_preflight

import rego.v1

# The milliCPU form ("100m") and any fraction that is not a multiple of
# 0.25 are rejected by the same check, so they are one rule.
violation contains make_diag_full("pf-batch-jd-eks-cpu-value", "ERROR", name,
	"Properties.EksProperties.PodProperties.Containers",
	sprintf("the cpu value %v is not valid (\"Value %v for type cpu in resources is not valid. Provide a valid number and unit.\")", [v, v]),
	"Use a whole number of vCPUs or a multiple of 0.25",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_EksContainerResourceRequirements.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	some c in _pf_batch_eks_containers(name)
	bad := [v | some v in _pf_batch_eks_vals(c.value, "cpu"); _pf_batch_eks_cpu_bad(v)]
	count(bad) > 0
	v := bad[0]
}
