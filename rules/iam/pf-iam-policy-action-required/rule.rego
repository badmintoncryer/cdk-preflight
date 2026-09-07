package cdk_preflight

import rego.v1

_pf_iamar_none(s) if {
	object.get(s, "Action", "__pf_absent") == "__pf_absent"
	object.get(s, "NotAction", "__pf_absent") == "__pf_absent"
}

_pf_iamar_none(s) if {
	a := object.get(s, "Action", null)
	is_array(a)
	count(a) == 0
}

violation contains make_diag_full("pf-iam-policy-action-required", "ERROR", name,
	sprintf("%s.Statement.%d", [path, i]),
	"Policy statement carries no Action or NotAction; IAM rejects the document with \"Policy statement must contain actions.\"",
	"Add an Action (or NotAction) to the statement, or drop the statement",
	"https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_action.html") if {
	some [name, path, d] in _pf_iamlib_all
	some [i, s] in _pf_iamlib_stmts(d)
	is_object(s)
	_pf_iamar_none(s)
}
