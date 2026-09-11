package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jd-fargate-privileged", "ERROR", name,
	"Properties.ContainerProperties.Privileged",
	"a Fargate job definition sets Privileged (\"Fargate requires that the \u2018privileged\u2019 setting be \u2018false\u2019 at the container level.\")",
	"Remove Privileged, or run the job on EC2",
	"https://docs.aws.amazon.com/batch/latest/userguide/fargate-job-definitions.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	_pf_batch_fargate(name)
	_pf_batch_cpget(name, "Privileged") == true
}
