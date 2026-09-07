package cdk_preflight

import rego.v1

_pf_iamsr_empty(d) if {
	object.get(d, "Statement", "__pf_absent") == "__pf_absent"
}

_pf_iamsr_empty(d) if {
	arr := object.get(d, "Statement", null)
	is_array(arr)
	count(arr) == 0
}

violation contains make_diag_full("pf-iam-policy-statement-required", "ERROR", name,
	path,
	"Policy document carries no statement; IAM rejects it with \"Syntax errors in policy.\"",
	"Give the document at least one statement, or drop the policy altogether (an empty policy is not a way to grant nothing)",
	"https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_grammar.html") if {
	some [name, path, d] in _pf_iamlib_all
	_pf_iamsr_empty(d)
}
