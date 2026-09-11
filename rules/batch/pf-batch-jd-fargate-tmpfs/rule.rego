package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jd-fargate-tmpfs", "ERROR", name,
	"Properties.ContainerProperties.LinuxParameters.Tmpfs",
	"a Fargate job definition sets LinuxParameters.Tmpfs (\"linuxParameter.tmpfs is not allowed for Fargate.\")",
	"Remove Tmpfs, or run the job on EC2",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_LinuxParameters.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	_pf_batch_fargate(name)
	_pf_batch_ohas(_pf_batch_lp(name), "Tmpfs")
}
