package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-iam-policy-condition-null-ifexists", "ERROR", name,
	sprintf("%s.Statement.%d.Condition.%s", [path, i, op]),
	sprintf("Condition operator '%s' does not exist: Null already tests for a missing key, so it takes no IfExists suffix, and IAM rejects the document with \"Syntax errors in policy.\"", [op]),
	"Use the bare Null operator (\"Null\": {\"key\": \"true\"}) — the IfExists suffix belongs to the value-comparing operators",
	"https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html") if {
	some [name, path, d] in _pf_iamlib_all
	some [i, s] in _pf_iamlib_stmts(d)
	is_object(s)
	some [op, _, _] in _pf_iamlib_conds(s)
	_pf_iamlib_op_root(op) == "Null"
	endswith(_pf_iamlib_op_unprefixed(op), "IfExists")
}
