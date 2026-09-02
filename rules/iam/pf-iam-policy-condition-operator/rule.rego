package cdk_preflight

import rego.v1

# Base operators plus the IfExists suffix and set-operator prefixes.
# A typo like StringEqual/StringEqualz is unreachable for every other
# layer because the document is opaque json.
_pf_ico_base := {
	"StringEquals", "StringNotEquals", "StringEqualsIgnoreCase", "StringNotEqualsIgnoreCase",
	"StringLike", "StringNotLike",
	"NumericEquals", "NumericNotEquals", "NumericLessThan", "NumericLessThanEquals",
	"NumericGreaterThan", "NumericGreaterThanEquals",
	"DateEquals", "DateNotEquals", "DateLessThan", "DateLessThanEquals",
	"DateGreaterThan", "DateGreaterThanEquals",
	"Bool", "BinaryEquals", "IpAddress", "NotIpAddress",
	"ArnEquals", "ArnLike", "ArnNotEquals", "ArnNotLike", "Null",
}

_pf_ico_docs contains [name, path, d] if {
	some name in resources_of_type("AWS::IAM::Role")
	some p in flatten_list(name, "Properties.Policies")
	is_object(p.value)
	d := object.get(p.value, "PolicyDocument", {})
	is_object(d)
	path := sprintf("Properties.Policies.%d.PolicyDocument", [p.index])
}

_pf_ico_docs contains [name, path, d] if {
	some t in {"AWS::IAM::Policy", "AWS::IAM::ManagedPolicy"}
	some name in resources_of_type(t)
	props := input.resources[name].properties
	is_object(props)
	d := object.get(props, "PolicyDocument", {})
	is_object(d)
	path := "Properties.PolicyDocument"
}

_pf_ico_stmts(d) := [[0, s]] if {
	s := object.get(d, "Statement", "__pf_absent")
	is_object(s)
}

_pf_ico_stmts(d) := out if {
	arr := object.get(d, "Statement", "__pf_absent")
	is_array(arr)
	out := [[i, s] | some i, s in arr]
}

# Strip an optional ForAllValues:/ForAnyValue: prefix, then IfExists.
_pf_ico_unprefixed(op) := parts[count(parts) - 1] if parts := split(op, ":")

_pf_ico_root(op) := substring(b, 0, count(b) - 8) if {
	b := _pf_ico_unprefixed(op)
	endswith(b, "IfExists")
}

_pf_ico_root(op) := b if {
	b := _pf_ico_unprefixed(op)
	not endswith(b, "IfExists")
}

violation contains make_diag_full("pf-iam-policy-condition-operator", "ERROR", name,
	sprintf("%s.Statement.%d.Condition", [path, i]),
	sprintf("Condition operator '%s' does not exist; the policy is rejected with \"Syntax errors in policy.\"", [op]),
	"Use a documented operator (StringEquals, ArnLike, ...), optionally with IfExists or a ForAllValues:/ForAnyValue: prefix",
	"https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html") if {
	some [name, path, d] in _pf_ico_docs
	some [i, s] in _pf_ico_stmts(d)
	is_object(s)
	cond := object.get(s, "Condition", {})
	is_object(cond)
	some op, _ in cond
	is_string(op)
	not _pf_ico_root(op) in _pf_ico_base
}
