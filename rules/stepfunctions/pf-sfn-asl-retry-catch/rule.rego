package cdk_preflight

import rego.v1

_pf_sfnrc_url := "https://docs.aws.amazon.com/step-functions/latest/dg/concepts-error-handling.html"

_pf_sfnrc_fix := "Move the States.ALL catch-all to the last entry by itself; give every catcher a Next"

# [name, path, state name, field, index, entry, entries count]
_pf_sfnrc_entry contains [name, p, sname, field, i, e, n] if {
	some [name, p, s, sname, st] in _pf_sfnlib_states
	some field in ["Retry", "Catch"]
	arr := object.get(st, field, null)
	is_array(arr)
	n := count(arr)
	some i, e in arr
	is_object(e)
}

violation contains make_diag_full("pf-sfn-asl-retry-catch", "ERROR", name,
	sprintf("%s.%s[%d]", [_pf_sfnlib_path(name, p, sname), field, i]),
	sprintf("state '%s' %s[%d] has no ErrorEquals; CreateStateMachine fails with \"SCHEMA_VALIDATION_FAILED: These fields are required: [ErrorEquals]\"", [sname, field, i]),
	_pf_sfnrc_fix, _pf_sfnrc_url) if {
	some [name, p, sname, field, i, e, _] in _pf_sfnrc_entry
	not _pf_sfnlib_has(e, "ErrorEquals")
}

violation contains make_diag_full("pf-sfn-asl-retry-catch", "ERROR", name,
	sprintf("%s.%s[%d].ErrorEquals", [_pf_sfnlib_path(name, p, sname), field, i]),
	sprintf("state '%s' %s[%d] has an empty ErrorEquals; CreateStateMachine fails with \"SCHEMA_VALIDATION_FAILED: Value cannot be empty\"", [sname, field, i]),
	_pf_sfnrc_fix, _pf_sfnrc_url) if {
	some [name, p, sname, field, i, e, _] in _pf_sfnrc_entry
	ee := object.get(e, "ErrorEquals", null)
	is_array(ee)
	count(ee) == 0
}

violation contains make_diag_full("pf-sfn-asl-retry-catch", "ERROR", name,
	sprintf("%s.%s[%d].ErrorEquals", [_pf_sfnlib_path(name, p, sname), field, i]),
	sprintf("state '%s' %s[%d] lists States.ALL together with other error names; CreateStateMachine fails with \"SCHEMA_VALIDATION_FAILED: States.ALL must appear alone and at end of list\"", [sname, field, i]),
	_pf_sfnrc_fix, _pf_sfnrc_url) if {
	some [name, p, sname, field, i, e, _] in _pf_sfnrc_entry
	ee := object.get(e, "ErrorEquals", null)
	is_array(ee)
	"States.ALL" in ee
	count(ee) > 1
}

violation contains make_diag_full("pf-sfn-asl-retry-catch", "ERROR", name,
	sprintf("%s.%s[%d].ErrorEquals", [_pf_sfnlib_path(name, p, sname), field, i]),
	sprintf("state '%s' %s[%d] catches States.ALL but is not the last entry (%d entries); CreateStateMachine fails with \"SCHEMA_VALIDATION_FAILED: States.ALL must appear alone and at end of list\"", [sname, field, i, n]),
	_pf_sfnrc_fix, _pf_sfnrc_url) if {
	some [name, p, sname, field, i, e, n] in _pf_sfnrc_entry
	ee := object.get(e, "ErrorEquals", null)
	is_array(ee)
	"States.ALL" in ee
	i < n - 1
}

violation contains make_diag_full("pf-sfn-asl-retry-catch", "ERROR", name,
	sprintf("%s.Catch[%d]", [_pf_sfnlib_path(name, p, sname), i]),
	sprintf("state '%s' Catch[%d] has no Next; CreateStateMachine fails with \"SCHEMA_VALIDATION_FAILED: These fields are required: [Next]\"", [sname, i]),
	_pf_sfnrc_fix, _pf_sfnrc_url) if {
	some [name, p, sname, field, i, e, _] in _pf_sfnrc_entry
	field == "Catch"
	not _pf_sfnlib_has(e, "Next")
}

violation contains make_diag_full("pf-sfn-asl-retry-catch", "ERROR", name,
	sprintf("%s.Retry[%d].JitterStrategy", [_pf_sfnlib_path(name, p, sname), i]),
	sprintf("state '%s' Retry[%d] JitterStrategy '%s' is not NONE or FULL; CreateStateMachine fails with \"SCHEMA_VALIDATION_FAILED: Value should be one of the following: [NONE, FULL]\"", [sname, i, j]),
	_pf_sfnrc_fix, _pf_sfnrc_url) if {
	some [name, p, sname, field, i, e, _] in _pf_sfnrc_entry
	field == "Retry"
	j := object.get(e, "JitterStrategy", null)
	is_string(j)
	not j in {"NONE", "FULL"}
}
