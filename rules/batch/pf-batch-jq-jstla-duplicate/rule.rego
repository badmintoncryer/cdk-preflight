package cdk_preflight

import rego.v1

# The measured rejection repeats both State and Reason; only that pair is
# claimed here, so a template the service would accept never fires.
violation contains make_diag_full("pf-batch-jq-jstla-duplicate", "ERROR", name,
	"Properties.JobStateTimeLimitActions",
	sprintf("%v entries repeat state %v with the same reason (\"Duplicate job state limit actions are not allowed.\")", [n, st]),
	"Keep one job state time limit action per state",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_JobStateTimeLimitAction.html") if {
	some name in resources_of_type("AWS::Batch::JobQueue")
	es := flatten_list(name, "Properties.JobStateTimeLimitActions")
	some e in es
	st := _pf_batch_oget(e.value, "State")
	rs := _pf_batch_oget(e.value, "Reason")
	n := count([1 | some x in es; object.get(x.value, "State", null) == st; object.get(x.value, "Reason", null) == rs])
	n > 1
}
