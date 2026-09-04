package cdk_preflight

import rego.v1

_pf_sfnnum_url := "https://docs.aws.amazon.com/step-functions/latest/dg/state-task.html"

_pf_sfnnum_fix := "Use a value inside the documented range (JSONata states may use a {% %} expression instead)"

# Measured with ValidateStateMachineDefinition on 2026-09-05. Retry
# IntervalSeconds 0 and the top-level TimeoutSeconds 0 are accepted, so they
# are deliberately absent here.
_pf_sfnnum_min contains ["TimeoutSeconds", 1]

_pf_sfnnum_min contains ["HeartbeatSeconds", 1]

_pf_sfnnum_min contains ["Seconds", 0]

_pf_sfnnum_min contains ["MaxConcurrency", 0]

_pf_sfnnum_max contains ["TimeoutSeconds", 99999999]

_pf_sfnnum_max contains ["HeartbeatSeconds", 99999999]

_pf_sfnnum_max contains ["Seconds", 99999999]

_pf_sfnnum_max contains ["ToleratedFailurePercentage", 100]

_pf_sfnnum_rmin contains ["MaxAttempts", 0]

_pf_sfnnum_rmin contains ["BackoffRate", 1]

_pf_sfnnum_rmin contains ["MaxDelaySeconds", 1]

_pf_sfnnum_rmax contains ["MaxAttempts", 99999999]

_pf_sfnnum_rmax contains ["MaxDelaySeconds", 31622400]

_pf_sfnnum_int := {"TimeoutSeconds", "HeartbeatSeconds", "Seconds", "MaxConcurrency", "ToleratedFailurePercentage", "ToleratedFailureCount"}

violation contains make_diag_full("pf-sfn-asl-numeric-ranges", "ERROR", name,
	sprintf("%s.%s", [_pf_sfnlib_path(name, p, sname), f]),
	sprintf("state '%s' %s is %v, below the minimum %v; CreateStateMachine fails with \"SCHEMA_VALIDATION_FAILED: Minimum value is %v\"", [sname, f, v, m, m]),
	_pf_sfnnum_fix, _pf_sfnnum_url) if {
	some [name, p, s, sname, st] in _pf_sfnlib_states
	some [f, m] in _pf_sfnnum_min
	v := object.get(st, f, null)
	is_number(v)
	v < m
}

violation contains make_diag_full("pf-sfn-asl-numeric-ranges", "ERROR", name,
	sprintf("%s.%s", [_pf_sfnlib_path(name, p, sname), f]),
	sprintf("state '%s' %s is %v, above the maximum %v; CreateStateMachine fails with \"SCHEMA_VALIDATION_FAILED: Maximum value is %v\"", [sname, f, v, m, m]),
	_pf_sfnnum_fix, _pf_sfnnum_url) if {
	some [name, p, s, sname, st] in _pf_sfnlib_states
	some [f, m] in _pf_sfnnum_max
	v := object.get(st, f, null)
	is_number(v)
	v > m
}

violation contains make_diag_full("pf-sfn-asl-numeric-ranges", "ERROR", name,
	sprintf("%s.%s", [_pf_sfnlib_path(name, p, sname), f]),
	sprintf("state '%s' %s is the string '%s'; the field takes an integer (or a {%% %%} JSONata expression), and CreateStateMachine fails with \"SCHEMA_VALIDATION_FAILED: Expected value of type Integer\"", [sname, f, v]),
	_pf_sfnnum_fix, _pf_sfnnum_url) if {
	some [name, p, s, sname, st] in _pf_sfnlib_states
	some f in _pf_sfnnum_int
	v := object.get(st, f, null)
	is_string(v)
	not startswith(v, "{%")
	not contains(v, "${")
}

violation contains make_diag_full("pf-sfn-asl-numeric-ranges", "ERROR", name,
	sprintf("%s.Retry[%d].%s", [_pf_sfnlib_path(name, p, sname), i, f]),
	sprintf("state '%s' Retry[%d] %s is %v, below the minimum %v; CreateStateMachine fails with \"SCHEMA_VALIDATION_FAILED: Minimum value is %v\"", [sname, i, f, v, m, m]),
	_pf_sfnnum_fix, _pf_sfnnum_url) if {
	some [name, p, s, sname, st] in _pf_sfnlib_states
	arr := object.get(st, "Retry", [])
	is_array(arr)
	some i, r in arr
	is_object(r)
	some [f, m] in _pf_sfnnum_rmin
	v := object.get(r, f, null)
	is_number(v)
	v < m
}

violation contains make_diag_full("pf-sfn-asl-numeric-ranges", "ERROR", name,
	sprintf("%s.Retry[%d].%s", [_pf_sfnlib_path(name, p, sname), i, f]),
	sprintf("state '%s' Retry[%d] %s is %v, above the maximum %v; CreateStateMachine fails with \"SCHEMA_VALIDATION_FAILED: Maximum value is %v\"", [sname, i, f, v, m, m]),
	_pf_sfnnum_fix, _pf_sfnnum_url) if {
	some [name, p, s, sname, st] in _pf_sfnlib_states
	arr := object.get(st, "Retry", [])
	is_array(arr)
	some i, r in arr
	is_object(r)
	some [f, m] in _pf_sfnnum_rmax
	v := object.get(r, f, null)
	is_number(v)
	v > m
}
