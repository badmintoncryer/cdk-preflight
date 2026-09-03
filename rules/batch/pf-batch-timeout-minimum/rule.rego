package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-timeout-minimum", "ERROR", name,
	"Properties.Timeout.AttemptDurationSeconds",
	sprintf("Timeout %v seconds is below the minimum (\"AttemptDurationSeconds in Timeout must be at least 60 seconds.\")", [n]),
	"Use at least 60 seconds",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_RegisterJobDefinition.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	n := to_number(resolve(name, "Properties.Timeout.AttemptDurationSeconds"))
	n < 60
}
