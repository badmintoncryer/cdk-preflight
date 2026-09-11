package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jd-runtime-platform-ec2-only", "ERROR", name,
	"Properties.ContainerProperties.RuntimePlatform",
	"an EC2 job definition sets RuntimePlatform (\"runtimePlatform is not applicable for EC2.\")",
	"Remove RuntimePlatform, or run the job on Fargate",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_RegisterJobDefinition.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	_pf_batch_ec2(name)
	_pf_batch_cphas(name, "RuntimePlatform")
}
