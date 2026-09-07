package cdk_preflight

import rego.v1

_pf_iamtas_ok := {
	"sts:AssumeRole", "sts:AssumeRoleWithWebIdentity", "sts:AssumeRoleWithSAML",
	"sts:TagSession", "sts:SetSourceIdentity", "sts:SetContext",
}

violation contains make_diag_full("pf-iam-trust-policy-action-sts-only", "ERROR", name,
	sprintf("%s.Statement.%d", [path, i]),
	sprintf("Trust policy action '%s' is not an STS AssumeRole action; IAM rejects the role with \"AssumeRole policy may only specify STS AssumeRole actions.\"", [v]),
	"A trust policy answers \"who may assume this role\": keep it to sts:AssumeRole (or the WithWebIdentity / WithSAML / TagSession / SetSourceIdentity / SetContext variants) and put permissions in an attached policy — wildcards including sts:* are rejected too",
	"https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-custom.html") if {
	some [name, path, d] in _pf_iamlib_trusts
	some [i, s] in _pf_iamlib_stmts(d)
	is_object(s)
	some v in _pf_iamlib_actions(s)
	is_string(v)
	not v in _pf_iamtas_ok
}
