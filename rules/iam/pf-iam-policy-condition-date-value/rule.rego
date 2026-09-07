package cdk_preflight

import rego.v1

_pf_iamcdv_ok(v) if regex.match(`^[0-9]+$`, v)

_pf_iamcdv_ok(v) if regex.match(`^[0-9]{4}(-(0[1-9]|1[0-2])(-(0[1-9]|[12][0-9]|3[01])([T ][0-9]{2}:[0-9]{2}(:[0-9]{2}(\.[0-9]+)?)?(Z|[+-][0-9]{2}:?[0-9]{2})?)?)?)?$`, v)

violation contains make_diag_full("pf-iam-policy-condition-date-value", "ERROR", name,
	sprintf("%s.Statement.%d.Condition.%s", [path, i, op]),
	sprintf("Date condition operator '%s' takes an ISO 8601 date or epoch seconds; '%s' is neither and IAM rejects the document with \"The policy failed legacy parsing\"", [op, v]),
	"Write the value as 2026-01-01T00:00:00Z (or epoch seconds); policy variables cannot be used with Date operators",
	"https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html") if {
	some [name, path, d] in _pf_iamlib_all
	some [i, s] in _pf_iamlib_stmts(d)
	is_object(s)
	some [op, _, raw] in _pf_iamlib_conds(s)
	startswith(_pf_iamlib_op_root(op), "Date")
	some v in _pf_iamlib_list(raw)
	is_string(v)
	not _pf_iamcdv_ok(v)
}
