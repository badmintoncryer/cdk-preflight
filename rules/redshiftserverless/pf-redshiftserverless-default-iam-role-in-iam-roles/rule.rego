package cdk_preflight

import rego.v1

# resolve() turns a Ref / GetAtt into the target's logical id and leaves a literal ARN
# as is, so both sides are compared in the same currency only when they are of the same
# kind: two logical ids of resources in this template, or two literal ARNs. A mixed or
# unresolvable list (Fn::Sub over a resource, a Ref to a list parameter) cannot be judged.
_pf_rssdir_lit(v) if {
	is_string(v)
	startswith(v, "arn:")
}

_pf_rssdir_ref(v) if {
	is_string(v)
	input.resources[v]
}

_pf_rssdir_comparable(a, b) if {
	_pf_rssdir_lit(a)
	_pf_rssdir_lit(b)
}

_pf_rssdir_comparable(a, b) if {
	_pf_rssdir_ref(a)
	_pf_rssdir_ref(b)
}

# The raw IamRoles list; an absent list reads as empty, which the service rejects too
# ("The IAM roles list isnt specified").
_pf_rssdir_arr(name) := object.get(_pf_rsslib_props(name), "IamRoles", [])

# Namespaces whose IamRoles the rule cannot compare with the default role.
_pf_rssdir_odd contains name if {
	some name in resources_of_type("AWS::RedshiftServerless::Namespace")
	not is_array(_pf_rssdir_arr(name))
}

_pf_rssdir_odd contains name if {
	some name in resources_of_type("AWS::RedshiftServerless::Namespace")
	arr := _pf_rssdir_arr(name)
	is_array(arr)
	d := resolve(name, "Properties.DefaultIamRoleArn")
	some i, _ in arr
	not _pf_rssdir_comparable(d, resolve(name, sprintf("Properties.IamRoles.%d", [i])))
}

# [namespace, resolved role] for every entry of IamRoles.
_pf_rssdir_role contains [name, r] if {
	some name in resources_of_type("AWS::RedshiftServerless::Namespace")
	arr := _pf_rssdir_arr(name)
	is_array(arr)
	some i, _ in arr
	r := resolve(name, sprintf("Properties.IamRoles.%d", [i]))
	is_string(r)
}

violation contains make_diag_full("pf-redshiftserverless-default-iam-role-in-iam-roles", "ERROR", name,
	"Properties.DefaultIamRoleArn",
	sprintf("DefaultIamRoleArn %v is not listed in IamRoles %v; CreateNamespace fails with \"Invalid default IAM Role ... The IAM roles list isnt specified or it doesnt contain a default IAM Role\"", [d, roles]),
	"Add the default role to IamRoles as well (IamRoles must contain every role the namespace uses, the default included)",
	"https://docs.aws.amazon.com/redshift-serverless/latest/APIReference/API_CreateNamespace.html") if {
	some name in resources_of_type("AWS::RedshiftServerless::Namespace")
	d := resolve(name, "Properties.DefaultIamRoleArn")
	_pf_rssdir_comparable(d, d)
	not _pf_rssdir_odd[name]
	not _pf_rssdir_role[[name, d]]
	roles := [r | _pf_rssdir_role[[name, r]]]
}
