package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-retry-attempts", "ERROR", name,
	"Properties.RetryStrategy.Attempts",
	sprintf("RetryStrategy.Attempts %v is above the maximum (\"RetryAttempts must be between 1 and 10.\")", [n]),
	"Use at most 10 attempts",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_RegisterJobDefinition.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	n := to_number(resolve(name, "Properties.RetryStrategy.Attempts"))
	n > 10
}
