package cdk_preflight

import rego.v1

_pf_sfndup_url := "https://docs.aws.amazon.com/step-functions/latest/dg/state-parallel.html"

_pf_sfndup_fix := "Rename one of the states; names are global to the state machine, not to the branch"

violation contains make_diag_full("pf-sfn-asl-duplicate-state-name", "ERROR", name,
	_pf_sfnlib_path(name, p2, sname),
	sprintf("state name '%s' is defined in both %s and %s; names must be unique across the whole state machine, and CreateStateMachine fails with \"DUPLICATE_STATE_NAME: Duplicate State name: %s\"", [sname, p1, p2, sname]),
	_pf_sfndup_fix, _pf_sfndup_url) if {
	some [name, p1, _, sname, _] in _pf_sfnlib_states
	some [n2, p2, _, sn2, _] in _pf_sfnlib_states
	n2 == name
	sn2 == sname
	p1 < p2
}
