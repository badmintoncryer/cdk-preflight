package cdk_preflight

import rego.v1

_pf_sfnnm_url := "https://docs.aws.amazon.com/step-functions/latest/dg/service-quotas.html"

_pf_sfnnm_fix := "Shorten the state name / Label; give each Distributed Map a distinct Label"

violation contains make_diag_full("pf-sfn-asl-name-limits", "ERROR", name,
	_pf_sfnlib_path(name, p, sname),
	sprintf("state name '%s' is %d characters long (maximum 80); CreateStateMachine fails with \"INVALID_STATE_NAME: ... exceeds the 80-character limit allowed by the service\"", [sname, count(sname)]),
	_pf_sfnnm_fix, _pf_sfnnm_url) if {
	some [name, p, s, sname, st] in _pf_sfnlib_states
	count(sname) > 80
}

violation contains make_diag_full("pf-sfn-asl-name-limits", "ERROR", name,
	sprintf("%s.Label", [_pf_sfnlib_path(name, p, sname)]),
	sprintf("state '%s' Label is %d characters long (maximum 40); CreateStateMachine fails with \"INVALID_LABEL_NAME: ... exceeds the 40-character limit allowed by the service\"", [sname, count(l)]),
	_pf_sfnnm_fix, _pf_sfnnm_url) if {
	some [name, p, s, sname, st] in _pf_sfnlib_states
	l := object.get(st, "Label", null)
	is_string(l)
	count(l) > 40
}

_pf_sfnnm_label contains [name, path, l] if {
	some [name, p, s, sname, st] in _pf_sfnlib_states
	l := object.get(st, "Label", null)
	is_string(l)
	path := _pf_sfnlib_path(name, p, sname)
}

violation contains make_diag_full("pf-sfn-asl-name-limits", "ERROR", name,
	sprintf("%s.Label", [path2]),
	sprintf("Label '%s' is used by both %s and %s; Map labels must be unique, and CreateStateMachine fails with \"DUPLICATE_LABEL_NAME: Duplicate Label name: %s\"", [l, path1, path2, l]),
	_pf_sfnnm_fix, _pf_sfnnm_url) if {
	some [name, path1, l] in _pf_sfnnm_label
	some [n2, path2, l2] in _pf_sfnnm_label
	n2 == name
	l2 == l
	path1 < path2
}
