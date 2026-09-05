package cdk_preflight

import rego.v1

_pf_sfnne_url := "https://docs.aws.amazon.com/step-functions/latest/dg/statemachine-structure.html"

_pf_sfnne_fix := "Keep either Next (transition) or End: true (terminal) on the state, never both and never neither"

_pf_sfnne_types := {"Task", "Pass", "Wait", "Parallel", "Map"}

violation contains make_diag_full("pf-sfn-asl-next-end", "ERROR", name,
	_pf_sfnlib_path(name, p, sname),
	sprintf("state '%s' has both Next and End: true; CreateStateMachine fails with \"SCHEMA_VALIDATION_FAILED: There should only be one of the following fields: [Next, End]\"", [sname]),
	_pf_sfnne_fix, _pf_sfnne_url) if {
	some [name, p, s, sname, st] in _pf_sfnlib_states
	object.get(st, "Type", null) in _pf_sfnne_types
	_pf_sfnlib_has(st, "Next")
	object.get(st, "End", false) == true
}

violation contains make_diag_full("pf-sfn-asl-next-end", "ERROR", name,
	_pf_sfnlib_path(name, p, sname),
	sprintf("state '%s' has neither Next nor End: true, so the execution cannot leave it; CreateStateMachine fails with \"SCHEMA_VALIDATION_FAILED: This object should have only one of the following fields: [Next, End]\"", [sname]),
	_pf_sfnne_fix, _pf_sfnne_url) if {
	some [name, p, s, sname, st] in _pf_sfnlib_states
	object.get(st, "Type", null) in _pf_sfnne_types
	not _pf_sfnlib_has(st, "Next")
	object.get(st, "End", false) != true
}
