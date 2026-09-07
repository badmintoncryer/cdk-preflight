package cdk_preflight

import rego.v1

_pf_iamcav_ok(v) if v == "*"

_pf_iamcav_ok(v) if {
	startswith(v, "arn:")
	count(split(v, ":")) >= 6
}

violation contains make_diag_full("pf-iam-policy-condition-arn-value", "ERROR", name,
	sprintf("%s.Statement.%d.Condition.%s", [path, i, op]),
	sprintf("Condition operator '%s' compares ARNs but '%s' is not one; IAM rejects the document with \"The policy failed legacy parsing\"", [op, v]),
	"Compare against a full ARN (arn:partition:service:region:account:resource, wildcards allowed inside) or use a String* operator",
	"https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html") if {
	some [name, path, d] in _pf_iamlib_all
	some [i, s] in _pf_iamlib_stmts(d)
	is_object(s)
	some [op, _, raw] in _pf_iamlib_conds(s)
	startswith(_pf_iamlib_op_root(op), "Arn")
	some v in _pf_iamlib_list(raw)
	is_string(v)
	not _pf_iamcav_ok(v)
}
