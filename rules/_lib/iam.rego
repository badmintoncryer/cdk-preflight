package cdk_preflight

import rego.v1

# Shared helpers for the IAM rules (rules/iam/pf-iam-*).
# Loaded ahead of every rule (BUNDLED_LIBS); never emits diagnostics.
#
# A policy document is opaque to every earlier layer: the L2 accepts objects and
# minimizes them after validateTree (aws-iam/lib/policy-document.ts:222), and the
# bundled engine carries no IAM policy semantics at all. The collectors below give
# every rule one view of "each policy document in this template", split by the two
# IAM validators that see them — identity/resource documents (PutRolePolicy,
# CreatePolicy) and role trust documents (CreateRole, UpdateAssumeRolePolicy) —
# because the same grammar is judged by different rules on each side.

# Identity documents embedded in an identity resource.
_pf_iamlib_docs contains [name, path, d] if {
	some t in {"AWS::IAM::Role", "AWS::IAM::User", "AWS::IAM::Group"}
	some name in resources_of_type(t)
	some p in flatten_list(name, "Properties.Policies")
	is_object(p.value)
	d := object.get(p.value, "PolicyDocument", null)
	is_object(d)
	path := sprintf("Properties.Policies.%d.PolicyDocument", [p.index])
}

# Stand-alone policy resources.
_pf_iamlib_docs contains [name, "Properties.PolicyDocument", d] if {
	some t in {
		"AWS::IAM::Policy", "AWS::IAM::ManagedPolicy",
		"AWS::IAM::RolePolicy", "AWS::IAM::UserPolicy", "AWS::IAM::GroupPolicy",
	}
	some name in resources_of_type(t)
	props := input.resources[name].properties
	is_object(props)
	d := object.get(props, "PolicyDocument", null)
	is_object(d)
}

# Role trust documents.
_pf_iamlib_trusts contains [name, "Properties.AssumeRolePolicyDocument", d] if {
	some name in resources_of_type("AWS::IAM::Role")
	props := input.resources[name].properties
	is_object(props)
	d := object.get(props, "AssumeRolePolicyDocument", null)
	is_object(d)
}

# Every policy document, for the rules about the grammar both sides share.
_pf_iamlib_all contains x if {
	some x in _pf_iamlib_docs
}

_pf_iamlib_all contains x if {
	some x in _pf_iamlib_trusts
}

# Statements as [index, statement]. A single statement object is index 0.
_pf_iamlib_stmts(d) := [[0, s]] if {
	s := object.get(d, "Statement", null)
	is_object(s)
}

_pf_iamlib_stmts(d) := out if {
	arr := object.get(d, "Statement", null)
	is_array(arr)
	out := [[i, s] | some i, s in arr]
}

# A scalar-or-list policy value as a list.
_pf_iamlib_list(v) := [v] if is_string(v)

_pf_iamlib_list(v) := v if is_array(v)

# Every Action / NotAction entry of one statement.
_pf_iamlib_actions(s) := out if {
	out := [v |
		some k in ["Action", "NotAction"]
		some v in _pf_iamlib_list(object.get(s, k, null))
	]
}

# Every Resource / NotResource entry of one statement.
_pf_iamlib_resources(s) := out if {
	out := [v |
		some k in ["Resource", "NotResource"]
		some v in _pf_iamlib_list(object.get(s, k, null))
	]
}

# Condition entries as [operator, key, raw value].
_pf_iamlib_conds(s) := out if {
	c := object.get(s, "Condition", {})
	is_object(c)
	out := [[op, k, v] |
		some op, kv in c
		is_object(kv)
		some k, v in kv
	]
}

# Principal entries as [type, value]; type is AWS / Service / Federated / CanonicalUser.
_pf_iamlib_principals(s, key) := out if {
	p := object.get(s, key, null)
	is_object(p)
	out := [[t, v] |
		some t, raw in p
		some v in _pf_iamlib_list(raw)
	]
}

# Operator without the ForAllValues:/ForAnyValue: prefix.
_pf_iamlib_op_unprefixed(op) := parts[count(parts) - 1] if parts := split(op, ":")

# Operator root: prefix and the IfExists suffix removed.
_pf_iamlib_op_root(op) := substring(b, 0, count(b) - 8) if {
	b := _pf_iamlib_op_unprefixed(op)
	endswith(b, "IfExists")
}

_pf_iamlib_op_root(op) := b if {
	b := _pf_iamlib_op_unprefixed(op)
	not endswith(b, "IfExists")
}

# Intrinsics and dynamic references surface as marker objects at any depth, so an
# object-shaped value is only "user wrote an object" when no key is a marker.
_pf_iamlib_marker(v) if {
	some k, _ in v
	startswith(k, "__")
}

# Partition of the deploy account. Undefined when the region is not injected
# (warn mode / region-agnostic app), which silently skips the partition rules.
_pf_iamlib_partition := "aws-cn" if startswith(data.cdk_preflight.deploy_region, "cn-")

_pf_iamlib_partition := "aws-us-gov" if startswith(data.cdk_preflight.deploy_region, "us-gov-")

_pf_iamlib_partition := "aws-iso-b" if startswith(data.cdk_preflight.deploy_region, "us-isob-")

_pf_iamlib_partition := "aws-iso" if startswith(data.cdk_preflight.deploy_region, "us-iso-")

_pf_iamlib_partition := "aws" if {
	r := data.cdk_preflight.deploy_region
	not startswith(r, "cn-")
	not startswith(r, "us-gov-")
	not startswith(r, "us-iso-")
	not startswith(r, "us-isob-")
}

# --- a role that another resource hands to a service --------------------------
# A property that names a role for a service to assume (an API Gateway
# integration's Credentials, an EventBridge target's RoleArn) is checked only when
# that service first assumes the role, after the deploy. This gives the logical id
# of the role when the value is Fn::GetAtt <role>.Arn of a role in this template
# whose trust policy can be read in full and no statement names `svc` as a Service
# principal. Anything that would need the trust policy evaluated (Deny,
# NotPrincipal, a "*" principal, intrinsics anywhere in a Principal) is not judged;
# Conditions are not read, so a role that names the service is never reported.
_pf_iamlib_role_without_service(v, svc) := id if {
	is_object(v)
	object.get(v, "__kind", "") == "getatt:Arn"
	id := object.get(v, "__ref", null)
	id in resources_of_type("AWS::IAM::Role")
	some [r, _, d] in _pf_iamlib_trusts
	r == id
	not _pf_iamlib_marker(d)
	stmts := _pf_iamlib_stmts(d)
	count(stmts) > 0
	every pair in stmts {
		_pf_iamlib_trust_readable(pair[1])
		svcs := _pf_iamlib_list(object.get(object.get(pair[1], "Principal", {}), "Service", []))
		not svc in svcs
		not concat("", [svc, ".cn"]) in svcs
	}
}

_pf_iamlib_trust_readable(s) if {
	is_object(s)
	object.get(s, "Effect", null) == "Allow"
	object.get(s, "NotPrincipal", "__pf_absent") == "__pf_absent"
	p := object.get(s, "Principal", null)
	is_object(p)
	not _pf_iamlib_marker(p)
	every _, raw in p {
		vals := _pf_iamlib_list(raw)
		every x in vals {
			is_string(x)
			x != "*"
		}
	}
}
