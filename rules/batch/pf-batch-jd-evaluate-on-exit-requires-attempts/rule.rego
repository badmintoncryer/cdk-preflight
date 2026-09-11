package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jd-evaluate-on-exit-requires-attempts", "ERROR", name,
	"Properties.RetryStrategy.Attempts",
	"EvaluateOnExit is set but Attempts is missing (\"RetryAttempts must be provided with retry strategy.\")",
	"Set RetryStrategy.Attempts",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_RetryStrategy.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	rs := _pf_batch_get(name, "RetryStrategy")
	_pf_batch_ohas(rs, "EvaluateOnExit")
	not _pf_batch_ohas(rs, "Attempts")
}
