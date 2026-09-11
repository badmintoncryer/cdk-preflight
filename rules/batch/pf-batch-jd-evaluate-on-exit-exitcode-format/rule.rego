package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jd-evaluate-on-exit-exitcode-format", "ERROR", name,
	"Properties.RetryStrategy.EvaluateOnExit",
	sprintf("OnExitCode %v contains characters other than digits and * (\"Evaluate on exit condition contains restricted characters.\")", [v]),
	"Use digits and the * wildcard only",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_EvaluateOnExit.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	some e in flatten_list(name, "Properties.RetryStrategy.EvaluateOnExit")
	v := _pf_batch_oget(e.value, "OnExitCode")
	_pf_batch_lit(v)
	not regex.match(`^[0-9*]+$`, v)
}
