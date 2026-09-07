package cdk_preflight

import rego.v1

_pf_iamcnv_bad(v) if {
	is_string(v)
	not to_number(v)
}

violation contains make_diag_full("pf-iam-policy-condition-numeric-value", "ERROR", name,
	sprintf("%s.Statement.%d.Condition.%s", [path, i, op]),
	sprintf("Numeric condition operator '%s' compares numbers but the value '%s' is not one; IAM rejects the document with \"The policy failed legacy parsing\"", [op, v]),
	"Give the Numeric* operator a numeric value, or compare with a String* operator instead",
	"https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html") if {
	some [name, path, d] in _pf_iamlib_all
	some [i, s] in _pf_iamlib_stmts(d)
	is_object(s)
	some [op, _, raw] in _pf_iamlib_conds(s)
	startswith(_pf_iamlib_op_root(op), "Numeric")
	some v in _pf_iamlib_list(raw)
	_pf_iamcnv_bad(v)
}
