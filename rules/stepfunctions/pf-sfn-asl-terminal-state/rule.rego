package cdk_preflight

import rego.v1

_pf_sfnterm_url := "https://docs.aws.amazon.com/step-functions/latest/dg/statemachine-structure.html"

_pf_sfnterm_fix := "Mark the last state with End: true or end with a Succeed/Fail state"

_pf_sfnterm_ok(name) if {
	some [n, p, s, _] in _pf_sfnlib_scopes
	n == name
	p == "States"
	some _, st in s
	is_object(st)
	object.get(st, "End", false) == true
}

_pf_sfnterm_ok(name) if {
	some [n, p, s, _] in _pf_sfnlib_scopes
	n == name
	p == "States"
	some _, st in s
	is_object(st)
	object.get(st, "Type", null) in {"Succeed", "Fail"}
}

violation contains make_diag_full("pf-sfn-asl-terminal-state", "ERROR", name,
	sprintf("%s.States", [_pf_sfnlib_prop(name)]),
	"no top-level state is terminal (End: true, Succeed or Fail); CreateStateMachine fails with \"MISSING_END_STATE: Workflow has no terminal state\"",
	_pf_sfnterm_fix, _pf_sfnterm_url) if {
	some [name, p, s, _] in _pf_sfnlib_scopes
	p == "States"
	not _pf_sfnterm_ok(name)
}
