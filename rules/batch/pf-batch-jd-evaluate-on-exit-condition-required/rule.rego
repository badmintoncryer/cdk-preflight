package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jd-evaluate-on-exit-condition-required", "ERROR", name,
	"Properties.RetryStrategy.EvaluateOnExit",
	"an EvaluateOnExit entry sets none of OnExitCode, OnReason or OnStatusReason (\"EvaluateOnExit should contain at least one of onExitCode, onReason or onStatusReason\")",
	"Add OnExitCode, OnReason or OnStatusReason to the entry",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_EvaluateOnExit.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	some e in flatten_list(name, "Properties.RetryStrategy.EvaluateOnExit")
	is_object(e.value)
	not _pf_batch_anykey(e.value, {"OnExitCode", "OnReason", "OnStatusReason"})
}
