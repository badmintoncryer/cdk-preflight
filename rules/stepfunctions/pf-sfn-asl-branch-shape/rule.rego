package cdk_preflight

import rego.v1

_pf_sfnbr_url := "https://docs.aws.amazon.com/step-functions/latest/dg/state-parallel.html"

_pf_sfnbr_fix := "Give every branch and item processor a StartAt and a States object; a Parallel needs at least one branch"

violation contains make_diag_full("pf-sfn-asl-branch-shape", "ERROR", name,
	sprintf("%s.Branches", [_pf_sfnlib_path(name, p, sname)]),
	sprintf("Parallel state '%s' has an empty Branches array; CreateStateMachine fails with \"SCHEMA_VALIDATION_FAILED: Value cannot be empty\"", [sname]),
	_pf_sfnbr_fix, _pf_sfnbr_url) if {
	some [name, p, s, sname, st] in _pf_sfnlib_states
	object.get(st, "Type", null) == "Parallel"
	arr := object.get(st, "Branches", null)
	is_array(arr)
	count(arr) == 0
}

violation contains make_diag_full("pf-sfn-asl-branch-shape", "ERROR", name,
	sprintf("%s.Branches[%d]", [_pf_sfnlib_path(name, p, sname), i]),
	sprintf("Parallel state '%s' branch %d has no %s; CreateStateMachine fails with \"SCHEMA_VALIDATION_FAILED: These fields are required: [%s]\"", [sname, i, req, req]),
	_pf_sfnbr_fix, _pf_sfnbr_url) if {
	some [name, p, s, sname, st] in _pf_sfnlib_states
	arr := object.get(st, "Branches", [])
	is_array(arr)
	some i, b in arr
	is_object(b)
	some req in ["StartAt", "States"]
	not _pf_sfnlib_has(b, req)
}

violation contains make_diag_full("pf-sfn-asl-branch-shape", "ERROR", name,
	sprintf("%s.%s", [_pf_sfnlib_path(name, p, sname), key]),
	sprintf("Map state '%s' %s has no %s; CreateStateMachine fails with \"SCHEMA_VALIDATION_FAILED: These fields are required: [%s]\"", [sname, key, req, req]),
	_pf_sfnbr_fix, _pf_sfnbr_url) if {
	some [name, p, s, sname, st] in _pf_sfnlib_states
	some key in ["ItemProcessor", "Iterator"]
	proc := object.get(st, key, null)
	is_object(proc)
	some req in ["StartAt", "States"]
	not _pf_sfnlib_has(proc, req)
}
