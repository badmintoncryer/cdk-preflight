package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jd-evaluate-on-exit-pattern-length", "ERROR", name,
	"Properties.RetryStrategy.EvaluateOnExit",
	sprintf("%v is %v characters (\"Evaluate on exit condition cannot exceed 512 characters.\")", [k, count(v)]),
	"Shorten the condition to 512 characters",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_EvaluateOnExit.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	some e in flatten_list(name, "Properties.RetryStrategy.EvaluateOnExit")
	some k in ["OnExitCode", "OnReason", "OnStatusReason"]
	v := _pf_batch_oget(e.value, k)
	_pf_batch_lit(v)
	count(v) > 512
}
