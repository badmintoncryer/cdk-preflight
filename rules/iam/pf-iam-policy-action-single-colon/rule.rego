package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-iam-policy-action-single-colon", "ERROR", name,
	sprintf("%s.Statement.%d", [path, i]),
	sprintf("Action '%s' carries more than one colon; IAM rejects the document with \"Actions/Condition can contain only one colon.\"", [v]),
	"An action is <service-prefix>:<ApiName> — a single colon separates the two halves",
	"https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_action.html") if {
	some [name, path, d] in _pf_iamlib_all
	some [i, s] in _pf_iamlib_stmts(d)
	is_object(s)
	some v in _pf_iamlib_actions(s)
	is_string(v)
	count(split(v, ":")) > 2
}
