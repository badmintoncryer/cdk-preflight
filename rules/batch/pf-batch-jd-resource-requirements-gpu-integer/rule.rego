package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jd-resource-requirements-gpu-integer", "ERROR", name,
	"Properties.ContainerProperties.ResourceRequirements",
	sprintf("GPU is %v (\"Value %v for type GPU in resourceRequirement is not valid. Please provide a numeric value.\")", [v, v]),
	"Request a whole number of GPUs",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_ResourceRequirement.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	v := _pf_batch_rr(_pf_batch_cp(name), "GPU")
	_pf_batch_lit(v)
	not regex.match(`^[0-9]+$`, v)
}
