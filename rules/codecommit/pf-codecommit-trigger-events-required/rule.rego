package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-codecommit-trigger-events-required", "ERROR", name,
	sprintf("Properties.Triggers.%d.Events", [i]),
	"The trigger lists no events; the handler's PutRepositoryTriggers fails with \"Repository trigger events list cannot be empty\"",
	"List at least one event, or use 'all'",
	"https://docs.aws.amazon.com/codecommit/latest/APIReference/API_PutRepositoryTriggers.html") if {
	some name in resources_of_type("AWS::CodeCommit::Repository")
	some i, t in _pf_cclib_triggers(name)
	is_object(t)
	ev := object.get(t, "Events", [])
	is_array(ev)
	count(ev) == 0
}
