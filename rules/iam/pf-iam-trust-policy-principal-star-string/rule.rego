package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-iam-trust-policy-principal-star-string", "ERROR", name,
	sprintf("%s.Statement.%d.Principal", [path, i]),
	"Trust policy uses the bare string principal \"*\"; a role trust policy needs a typed principal and IAM rejects it with \"AssumeRolepolicy contained an invalid principal\"",
	"Write {\"AWS\": \"*\"} (and pair it with a Condition) — the bare \"*\" form only works in resource policies such as S3 bucket policies",
	"https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html") if {
	some [name, path, d] in _pf_iamlib_trusts
	some [i, s] in _pf_iamlib_stmts(d)
	is_object(s)
	object.get(s, "Principal", null) == "*"
}
