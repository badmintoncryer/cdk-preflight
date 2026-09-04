package cdk_preflight

import rego.v1

_pf_sfnunr_url := "https://docs.aws.amazon.com/step-functions/latest/dg/statemachine-structure.html"

_pf_sfnunr_fix := "Transition to the state from another state (Next/Default/Choices/Catch) or remove it"

# [name, scope path, from state, target state]
_pf_sfnunr_edge contains [name, p, sname, target] if {
	some [name, p, s, sname, st] in _pf_sfnlib_states
	some key in ["Next", "Default"]
	target := object.get(st, key, null)
	is_string(target)
}

_pf_sfnunr_edge contains [name, p, sname, target] if {
	some [name, p, s, sname, st] in _pf_sfnlib_states
	some field in ["Choices", "Catch"]
	arr := object.get(st, field, [])
	is_array(arr)
	some c in arr
	is_object(c)
	target := object.get(c, "Next", null)
	is_string(target)
}

_pf_sfnunr_in(name, p, t) if {
	some [n2, p2, from, t2] in _pf_sfnunr_edge
	n2 == name
	p2 == p
	t2 == t
	from != t
}

# ponytail: sound subset of the service's reachability check — a state with no
# incoming edge from another state is certainly unreachable, but a cycle of
# orphans passes (needs graph.reachable, which the engine lacks). A dangling
# StartAt is left to engine rule E3601.
violation contains make_diag_full("pf-sfn-asl-unreachable-state", "ERROR", name,
	_pf_sfnlib_path(name, p, sname),
	sprintf("state '%s' is not reachable: it is not the StartAt ('%s') and no other state in its States block transitions to it; CreateStateMachine fails with \"MISSING_TRANSITION_TARGET: State \\\"%s\\\" is not reachable.\"", [sname, sa, sname]),
	_pf_sfnunr_fix, _pf_sfnunr_url) if {
	some [name, p, s, sa] in _pf_sfnlib_scopes
	is_string(sa)
	sa in object.keys(s)
	some sname, st in s
	is_object(st)
	sname != sa
	not _pf_sfnunr_in(name, p, sname)
}
