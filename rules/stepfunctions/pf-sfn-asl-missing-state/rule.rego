package cdk_preflight

import rego.v1

_pf_sfnmiss_url := "https://docs.aws.amazon.com/step-functions/latest/dg/statemachine-structure.html"

_pf_sfnmiss_fix := "Point Next/Default/Choices[].Next/Catch[].Next at a state defined in the same States block"

# [name, scope path, scope states, state name, field label, target]
_pf_sfnmiss_ref contains [name, p, s, sname, key, target] if {
	some [name, p, s, sname, st] in _pf_sfnlib_states
	some key in ["Next", "Default"]
	target := object.get(st, key, null)
	is_string(target)
}

_pf_sfnmiss_ref contains [name, p, s, sname, key, target] if {
	some [name, p, s, sname, st] in _pf_sfnlib_states
	some field in ["Choices", "Catch"]
	arr := object.get(st, field, [])
	is_array(arr)
	some i, c in arr
	is_object(c)
	target := object.get(c, "Next", null)
	is_string(target)
	key := sprintf("%s[%d].Next", [field, i])
}

# NOTE: a dangling StartAt (top level and Parallel branches) is deliberately
# NOT checked here — the engine's built-in E3601 (ERROR/CFN_LINT) covers it
# (verified against 1.7.0-beta on 2026-09-05). A Branch may not transition to
# a state outside its own States block either: the service scopes names.
violation contains make_diag_full("pf-sfn-asl-missing-state", "ERROR", name,
	sprintf("%s.%s", [_pf_sfnlib_path(name, p, sname), key]),
	sprintf("state '%s' references state '%s' via %s, but no state with that name is defined in the same States block; CreateStateMachine fails with \"MISSING_TRANSITION_TARGET: Missing 'Next' target: %s\"", [sname, target, key, target]),
	_pf_sfnmiss_fix, _pf_sfnmiss_url) if {
	some [name, p, s, sname, key, target] in _pf_sfnmiss_ref
	not target in object.keys(s)
}
