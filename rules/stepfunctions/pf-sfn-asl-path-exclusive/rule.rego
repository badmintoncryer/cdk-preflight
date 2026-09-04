package cdk_preflight

import rego.v1

_pf_sfnpx_url := "https://docs.aws.amazon.com/step-functions/latest/dg/state-task.html"

_pf_sfnpx_fix := "Keep either the static field or its Path variant; give a Map state one ItemProcessor (Iterator is the legacy spelling)"

_pf_sfnpx_pair contains ["TimeoutSeconds", "TimeoutSecondsPath"]

_pf_sfnpx_pair contains ["HeartbeatSeconds", "HeartbeatSecondsPath"]

_pf_sfnpx_pair contains ["MaxConcurrency", "MaxConcurrencyPath"]

_pf_sfnpx_pair contains ["ToleratedFailurePercentage", "ToleratedFailurePercentagePath"]

_pf_sfnpx_pair contains ["Error", "ErrorPath"]

_pf_sfnpx_pair contains ["Cause", "CausePath"]

_pf_sfnpx_pair contains ["ItemProcessor", "Iterator"]

violation contains make_diag_full("pf-sfn-asl-path-exclusive", "ERROR", name,
	sprintf("%s.%s", [_pf_sfnlib_path(name, p, sname), b]),
	sprintf("state '%s' sets both %s and %s; CreateStateMachine fails with \"SCHEMA_VALIDATION_FAILED: There should only be one of the following fields: [%s, %s]\"", [sname, a, b, a, b]),
	_pf_sfnpx_fix, _pf_sfnpx_url) if {
	some [name, p, s, sname, st] in _pf_sfnlib_states
	some [a, b] in _pf_sfnpx_pair
	_pf_sfnlib_has(st, a)
	_pf_sfnlib_has(st, b)
}

violation contains make_diag_full("pf-sfn-asl-path-exclusive", "ERROR", name,
	_pf_sfnlib_path(name, p, sname),
	sprintf("Map state '%s' has neither ItemProcessor nor Iterator; CreateStateMachine fails with \"SCHEMA_VALIDATION_FAILED: This object should have only one of the following fields: [ItemProcessor, Iterator]\"", [sname]),
	_pf_sfnpx_fix, _pf_sfnpx_url) if {
	some [name, p, s, sname, st] in _pf_sfnlib_states
	object.get(st, "Type", null) == "Map"
	not _pf_sfnlib_has(st, "ItemProcessor")
	not _pf_sfnlib_has(st, "Iterator")
}
