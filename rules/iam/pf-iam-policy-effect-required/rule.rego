package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-iam-policy-effect-required", "ERROR", name,
	sprintf("%s.Statement.%d", [path, i]),
	"Policy statement carries no Effect; IAM rejects the document with \"Syntax errors in policy.\" (there is no implicit Allow)",
	"Add \"Effect\": \"Allow\" or \"Effect\": \"Deny\" to the statement",
	"https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_grammar.html") if {
	some [name, path, d] in _pf_iamlib_all
	some [i, s] in _pf_iamlib_stmts(d)
	is_object(s)
	object.get(s, "Effect", "__pf_absent") == "__pf_absent"
}
