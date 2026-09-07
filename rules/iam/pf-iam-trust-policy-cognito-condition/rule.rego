package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-iam-trust-policy-cognito-condition", "ERROR", name,
	sprintf("%s.Statement.%d", [path, i]),
	"Statement trusts cognito-identity.amazonaws.com without a Condition; IAM rejects the role with \"A condition block must be present for the Cognito provider\" because an unconditioned statement would trust every identity pool in every account",
	"Add a Condition pinning the pool, e.g. StringEquals on cognito-identity.amazonaws.com:aud (and usually ForAnyValue:StringLike on :amr)",
	"https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html") if {
	some [name, path, d] in _pf_iamlib_trusts
	some [i, s] in _pf_iamlib_stmts(d)
	is_object(s)
	some [t, v] in _pf_iamlib_principals(s, "Principal")
	t == "Federated"
	v == "cognito-identity.amazonaws.com"
	object.get(s, "Condition", "__pf_absent") == "__pf_absent"
}
