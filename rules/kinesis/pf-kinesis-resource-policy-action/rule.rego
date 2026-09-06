package cdk_preflight

import rego.v1

_pf_kinrpa_fix := "List explicit kinesis: actions — Kinesis rejects other vendors and every wildcard, including kinesis:*"

# A statement Action that is not a literal kinesis:<Operation>: another
# vendor's prefix ("Action field includes AWS services that are inconsistent
# with specified vendor") or any wildcard ("cannot contain invalid actions").
_pf_kinrpa_bad(a) if {
	is_string(a)
	not startswith(a, "kinesis:")
}

_pf_kinrpa_bad(a) if {
	is_string(a)
	indexof(a, "*") != -1
}

violation contains make_diag_full("pf-kinesis-resource-policy-action", "ERROR", name,
	sprintf("Properties.ResourcePolicy.Statement.%v.Action", [i]),
	sprintf("statement %v allows '%v'; PutResourcePolicy rejects it (only explicit kinesis: actions are accepted)", [i, a]),
	_pf_kinrpa_fix, "https://docs.aws.amazon.com/kinesis/latest/APIReference/API_PutResourcePolicy.html") if {
	some [name, i, s] in _pf_kinlib_statements
	a := object.get(s, "Action", null)
	_pf_kinrpa_bad(a)
}

violation contains make_diag_full("pf-kinesis-resource-policy-action", "ERROR", name,
	sprintf("Properties.ResourcePolicy.Statement.%v.Action.%v", [i, j]),
	sprintf("statement %v allows '%v'; PutResourcePolicy rejects it (only explicit kinesis: actions are accepted)", [i, a]),
	_pf_kinrpa_fix, "https://docs.aws.amazon.com/kinesis/latest/APIReference/API_PutResourcePolicy.html") if {
	some [name, i, s] in _pf_kinlib_statements
	acts := object.get(s, "Action", null)
	is_array(acts)
	some j, a in acts
	_pf_kinrpa_bad(a)
}
