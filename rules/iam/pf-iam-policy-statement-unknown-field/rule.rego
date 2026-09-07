package cdk_preflight

import rego.v1

_pf_iamsuf_known := {"Sid", "Effect", "Principal", "NotPrincipal", "Action", "NotAction", "Resource", "NotResource", "Condition"}

violation contains make_diag_full("pf-iam-policy-statement-unknown-field", "ERROR", name,
	sprintf("%s.Statement.%d.%s", [path, i, k]),
	sprintf("'%s' is not a policy statement element; IAM rejects the whole document with \"Syntax errors in policy.\" rather than ignoring the key", [k]),
	"Statement elements are Sid, Effect, Principal, NotPrincipal, Action, NotAction, Resource, NotResource and Condition — check the spelling and the plural",
	"https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_grammar.html") if {
	some [name, path, d] in _pf_iamlib_all
	some [i, s] in _pf_iamlib_stmts(d)
	is_object(s)
	some k, _ in s
	not k in _pf_iamsuf_known
}
