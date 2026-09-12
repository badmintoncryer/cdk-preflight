package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jd-eks-gpu-integer", "ERROR", name,
	"Properties.EksProperties.PodProperties.Containers",
	sprintf("the nvidia.com/gpu value %v is not a whole number (\"Value %v for type nvidia.com/gpu in resources is not valid.\")", [v, v]),
	"Request a whole number of GPUs",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_EksContainerResourceRequirements.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	some c in _pf_batch_eks_containers(name)
	bad := [v | some v in _pf_batch_eks_vals(c.value, "nvidia.com/gpu"); not regex.match(`^[0-9]+$`, v)]
	count(bad) > 0
	v := bad[0]
}
