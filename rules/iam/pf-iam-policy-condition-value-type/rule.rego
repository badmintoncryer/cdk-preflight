package cdk_preflight

import rego.v1

_pf_iamcvt_bad(v) if {
	is_object(v)
	not _pf_iamlib_marker(v)
}

_pf_iamcvt_bad(v) if {
	is_array(v)
	some e in v
	is_object(e)
	not _pf_iamlib_marker(e)
}

violation contains make_diag_full("pf-iam-policy-condition-value-type", "ERROR", name,
	sprintf("%s.Statement.%d.Condition.%s.%s", [path, i, op, k]),
	sprintf("Condition key '%s' is given an object; a condition value is a string (or a list of strings) and IAM rejects the document with \"Syntax errors in policy.\"", [k]),
	"Flatten the value: one condition key maps to a string or a list of strings, and nesting another operator inside is not part of the grammar",
	"https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html") if {
	some [name, path, d] in _pf_iamlib_all
	some [i, s] in _pf_iamlib_stmts(d)
	is_object(s)
	some [op, k, raw] in _pf_iamlib_conds(s)
	_pf_iamcvt_bad(raw)
}
