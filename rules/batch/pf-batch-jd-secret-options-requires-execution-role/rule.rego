package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jd-secret-options-requires-execution-role", "ERROR", name,
	"Properties.ContainerProperties.ExecutionRoleArn",
	"LogConfiguration.SecretOptions is set without ExecutionRoleArn (\"executionRoleArn cannot be empty when using secrets or secretOptions\")",
	"Set ContainerProperties.ExecutionRoleArn",
	"https://docs.aws.amazon.com/batch/latest/userguide/specifying-sensitive-data-secrets.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	cp := _pf_batch_cp(name)
	_pf_batch_ohas(_pf_batch_oget(cp, "LogConfiguration"), "SecretOptions")
	not _pf_batch_ohas(cp, "ExecutionRoleArn")
}
