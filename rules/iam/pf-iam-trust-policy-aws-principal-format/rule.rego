package cdk_preflight

import rego.v1

_pf_iamapf_ok(v) if v == "*"

_pf_iamapf_ok(v) if regex.match(`^[0-9]{12}$`, replace(v, "-", ""))

_pf_iamapf_ok(v) if regex.match(`^arn:[a-z0-9-]+:iam::[0-9]{12}:(root|(user|role|group)/[^*?]+)$`, v)

violation contains make_diag_full("pf-iam-trust-policy-aws-principal-format", "ERROR", name,
	sprintf("%s.Statement.%d.Principal.AWS", [path, i]),
	sprintf("AWS principal '%s' is not a 12-digit account id or an IAM ARN; IAM rejects the role with \"Invalid principal in policy\"", [v]),
	"Use the account id, arn:aws:iam::<account>:root, or the full arn:aws:iam::<account>:role/<name> — session ARNs (sts assumed-role) and wildcards inside an ARN are not principals",
	"https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html") if {
	some [name, path, d] in _pf_iamlib_trusts
	some [i, s] in _pf_iamlib_stmts(d)
	is_object(s)
	some [t, v] in _pf_iamlib_principals(s, "Principal")
	t == "AWS"
	is_string(v)
	not _pf_iamapf_ok(v)
}
