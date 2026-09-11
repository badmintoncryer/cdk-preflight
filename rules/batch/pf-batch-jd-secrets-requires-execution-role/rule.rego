package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jd-secrets-requires-execution-role", "ERROR", name,
	"Properties.ContainerProperties.ExecutionRoleArn",
	"ContainerProperties.Secrets is set without ExecutionRoleArn (\"executionRoleArn cannot be empty when using secrets or secretOptions\")",
	"Set ContainerProperties.ExecutionRoleArn",
	"https://docs.aws.amazon.com/batch/latest/userguide/specifying-sensitive-data-secrets.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	cp := _pf_batch_cp(name)
	_pf_batch_ohas(cp, "Secrets")
	not _pf_batch_ohas(cp, "ExecutionRoleArn")
}
