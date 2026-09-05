package cdk_preflight

import rego.v1

_pf_efspol_url := "https://docs.aws.amazon.com/efs/latest/APIReference/API_PutFileSystemPolicy.html"

_pf_efspol_fix := "Point Resource at this file system (Fn::GetAtt <FileSystem>.Arn) or drop it, and keep an Allow for elasticfilesystem:PutFileSystemPolicy unless you set BypassPolicyLockoutSafetyCheck"

_pf_efspol_pol(name) := v if {
	v := object.get(input.resources[name].properties, "FileSystemPolicy", null)
	is_object(v)
}

_pf_efspol_pol(name) := v if {
	raw := object.get(input.resources[name].properties, "FileSystemPolicy", null)
	is_string(raw)
	v := json.unmarshal(raw)
	is_object(v)
}

_pf_efspol_stmts(pol) := [s] if {
	s := object.get(pol, "Statement", null)
	is_object(s)
}

_pf_efspol_stmts(pol) := arr if {
	arr := object.get(pol, "Statement", null)
	is_array(arr)
}

_pf_efspol_list(v) := [v] if not is_array(v)

_pf_efspol_list(v) := v if is_array(v)

# A literal file-system ARN in the policy of a file system that this template
# is creating always names a different file system: the new id is not known
# until the stack runs.
violation contains make_diag_full("pf-efs-file-system-policy", "ERROR", name,
	"Properties.FileSystemPolicy",
	sprintf("the policy names '%s', which is not the file system it is attached to; PutFileSystemPolicy fails with \"Policy contains an invalid resource\"", [r]),
	_pf_efspol_fix, _pf_efspol_url) if {
	some name in resources_of_type("AWS::EFS::FileSystem")
	some s in _pf_efspol_stmts(_pf_efspol_pol(name))
	some r in _pf_efspol_list(object.get(s, "Resource", []))
	is_string(r)
	contains(r, ":file-system/fs-")
}

_pf_efspol_locks(s) if {
	object.get(s, "Effect", "") == "Deny"
	some a in _pf_efspol_list(object.get(s, "Action", []))
	a in {"*", "elasticfilesystem:*", "elasticfilesystem:PutFileSystemPolicy"}
}

violation contains make_diag_full("pf-efs-file-system-policy", "ERROR", name,
	"Properties.FileSystemPolicy",
	"the policy denies elasticfilesystem:PutFileSystemPolicy to every principal; PutFileSystemPolicy fails with \"This policy would prevent future FileSystemPolicy updates\" unless BypassPolicyLockoutSafetyCheck is true",
	_pf_efspol_fix, _pf_efspol_url) if {
	some name in resources_of_type("AWS::EFS::FileSystem")
	some s in _pf_efspol_stmts(_pf_efspol_pol(name))
	_pf_efspol_locks(s)
	_pf_efspol_all_principals(s)
	not _pf_efspol_bypass(name)
}

# resolve() is undefined for an absent property, so "not true" needs its own helper.
_pf_efspol_bypass(name) if resolve(name, "Properties.BypassPolicyLockoutSafetyCheck") == true

_pf_efspol_all_principals(s) if object.get(s, "Principal", null) == "*"

_pf_efspol_all_principals(s) if {
	p := object.get(s, "Principal", null)
	is_object(p)
	"*" in _pf_efspol_list(object.get(p, "AWS", []))
}
