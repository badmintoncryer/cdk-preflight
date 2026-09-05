package cdk_preflight

import rego.v1

_pf_sfnwait_url := "https://docs.aws.amazon.com/step-functions/latest/dg/state-wait.html"

_pf_sfnwait_fix := "Keep one timing field; write Timestamp as 2030-01-01T00:00:00Z"

_pf_sfnwait_fields := {"Seconds", "Timestamp", "SecondsPath", "TimestampPath"}

violation contains make_diag_full("pf-sfn-asl-wait-timing", "ERROR", name,
	_pf_sfnlib_path(name, p, sname),
	sprintf("Wait state '%s' sets %d of Seconds/Timestamp/SecondsPath/TimestampPath; exactly one is allowed, and CreateStateMachine fails with \"SCHEMA_VALIDATION_FAILED: There should only be one of the following fields: [SecondsPath, Seconds, TimestampPath, Timestamp]\"", [sname, n]),
	_pf_sfnwait_fix, _pf_sfnwait_url) if {
	some [name, p, s, sname, st] in _pf_sfnlib_states
	object.get(st, "Type", null) == "Wait"
	n := count({k | some k, _ in st; k in _pf_sfnwait_fields})
	n > 1
}

violation contains make_diag_full("pf-sfn-asl-wait-timing", "ERROR", name,
	sprintf("%s.Timestamp", [_pf_sfnlib_path(name, p, sname)]),
	sprintf("Wait state '%s' Timestamp '%s' is not an RFC3339 timestamp with an uppercase T separator and Z suffix; CreateStateMachine fails with \"SCHEMA_VALIDATION_FAILED: String does not match RFC3339 timestamp\"", [sname, ts]),
	_pf_sfnwait_fix, _pf_sfnwait_url) if {
	some [name, p, s, sname, st] in _pf_sfnlib_states
	object.get(st, "Type", null) == "Wait"
	ts := object.get(st, "Timestamp", null)
	is_string(ts)
	not startswith(ts, "{%")
	not regex.match("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}([.][0-9]+)?Z$", ts)
}
