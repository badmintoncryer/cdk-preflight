package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-codecommit-trigger-events-all-exclusive", "ERROR", name,
	sprintf("Properties.Triggers.%d.Events", [i]),
	"The trigger lists \"all\" alongside another event; the handler's PutRepositoryTriggers fails with \"Repository trigger events cannot contain 'all' and additional event types simultaneously\"",
	"Use 'all' on its own, or list the individual events without it",
	"https://docs.aws.amazon.com/codecommit/latest/APIReference/API_PutRepositoryTriggers.html") if {
	some name in resources_of_type("AWS::CodeCommit::Repository")
	some i, t in _pf_cclib_triggers(name)
	is_object(t)
	ev := object.get(t, "Events", [])
	is_array(ev)
	"all" in ev
	count(ev) > 1
}
