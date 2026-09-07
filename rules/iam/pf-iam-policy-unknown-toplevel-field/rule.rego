package cdk_preflight

import rego.v1

_pf_iamutf_known := {"Version", "Id", "Statement"}

violation contains make_diag_full("pf-iam-policy-unknown-toplevel-field", "ERROR", name,
	sprintf("%s.%s", [path, k]),
	sprintf("'%s' is not a policy document element; IAM rejects the whole document with \"Syntax errors in policy.\" rather than ignoring the key", [k]),
	"A policy document holds only Version, Id and Statement — comments and descriptions have no place in the grammar",
	"https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_grammar.html") if {
	some [name, path, d] in _pf_iamlib_all
	some k, _ in d
	not k in _pf_iamutf_known
}
