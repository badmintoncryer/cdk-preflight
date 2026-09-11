package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jd-resource-requirements-gpu-not-fargate", "ERROR", name,
	"Properties.ContainerProperties.ResourceRequirements",
	"a Fargate job definition asks for GPU (\"GPU is not applicable for Fargate.\")",
	"Drop the GPU requirement, or run the job on EC2",
	"https://docs.aws.amazon.com/batch/latest/userguide/fargate-job-definitions.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	_pf_batch_fargate(name)
	_pf_batch_rr(_pf_batch_cp(name), "GPU")
}
