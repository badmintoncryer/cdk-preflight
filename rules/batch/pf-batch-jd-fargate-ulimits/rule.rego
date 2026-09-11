package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jd-fargate-ulimits", "ERROR", name,
	"Properties.ContainerProperties.Ulimits",
	"a Fargate job definition sets Ulimits (\"ulimits is not applicable for Fargate.\")",
	"Remove Ulimits, or run the job on EC2",
	"https://docs.aws.amazon.com/batch/latest/userguide/fargate-job-definitions.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	_pf_batch_fargate(name)
	_pf_batch_cphas(name, "Ulimits")
}
