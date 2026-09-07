package cdk_preflight

import rego.v1

_pf_iamcbv_ok(v) if {
	regex.match(`^[A-Za-z0-9+/]+={0,2}$`, v)
	count(v) % 4 == 0
}

violation contains make_diag_full("pf-iam-policy-condition-binary-value", "ERROR", name,
	sprintf("%s.Statement.%d.Condition.%s", [path, i, op]),
	sprintf("BinaryEquals compares base64 text; '%s' is not valid base64 and IAM rejects the document with \"Syntax errors in policy.\"", [v]),
	"Base64-encode the value (padded to a multiple of four characters) before putting it in the condition",
	"https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html") if {
	some [name, path, d] in _pf_iamlib_all
	some [i, s] in _pf_iamlib_stmts(d)
	is_object(s)
	some [op, _, raw] in _pf_iamlib_conds(s)
	startswith(_pf_iamlib_op_root(op), "Binary")
	some v in _pf_iamlib_list(raw)
	is_string(v)
	not _pf_iamcbv_ok(v)
}
