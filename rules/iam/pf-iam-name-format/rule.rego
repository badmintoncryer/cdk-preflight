package cdk_preflight

import rego.v1

_pf_iamname_pat := `^[A-Za-z0-9+=,.@_-]+$`

_pf_iamname_prop(t, prop) := [name, path, v] if {
	some name in resources_of_type(t)
	v := resolve(name, sprintf("Properties.%s", [prop]))
	is_string(v)
	not regex.match(_pf_iamname_pat, v)
	path := sprintf("Properties.%s", [prop])
}

_pf_iamname_bad contains _pf_iamname_prop("AWS::IAM::Role", "RoleName")

_pf_iamname_bad contains _pf_iamname_prop("AWS::IAM::User", "UserName")

_pf_iamname_bad contains _pf_iamname_prop("AWS::IAM::Group", "GroupName")

_pf_iamname_bad contains _pf_iamname_prop("AWS::IAM::ManagedPolicy", "ManagedPolicyName")

_pf_iamname_bad contains [name, path, v] if {
	some t in {"AWS::IAM::Role", "AWS::IAM::User", "AWS::IAM::Group"}
	some name in resources_of_type(t)
	some p in flatten_list(name, "Properties.Policies")
	is_object(p.value)
	v := object.get(p.value, "PolicyName", null)
	is_string(v)
	not regex.match(_pf_iamname_pat, v)
	path := sprintf("Properties.Policies.%d.PolicyName", [p.index])
}

violation contains make_diag_full("pf-iam-name-format", "ERROR", name,
	path,
	sprintf("IAM name '%s' is rejected: only alphanumerics and + = , . @ _ - are accepted (non-ASCII text such as Japanese is rejected)", [v]),
	"Rename the entity using alphanumerics and + = , . @ _ - only",
	"https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateRole.html") if {
	some [name, path, v] in _pf_iamname_bad
}
