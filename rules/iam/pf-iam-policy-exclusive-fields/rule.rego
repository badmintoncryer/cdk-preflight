package cdk_preflight

import rego.v1

# Each pair is either-or per statement; both at once is a syntax error.
_pf_ief_docs contains [name, path, d] if {
	some name in resources_of_type("AWS::IAM::Role")
	some p in flatten_list(name, "Properties.Policies")
	is_object(p.value)
	d := object.get(p.value, "PolicyDocument", {})
	is_object(d)
	path := sprintf("Properties.Policies.%d.PolicyDocument", [p.index])
}

_pf_ief_docs contains [name, path, d] if {
	some t in {"AWS::IAM::Policy", "AWS::IAM::ManagedPolicy"}
	some name in resources_of_type(t)
	props := input.resources[name].properties
	is_object(props)
	d := object.get(props, "PolicyDocument", {})
	is_object(d)
	path := "Properties.PolicyDocument"
}

_pf_ief_stmts(d) := [[0, s]] if {
	s := object.get(d, "Statement", "__pf_absent")
	is_object(s)
}

_pf_ief_stmts(d) := out if {
	arr := object.get(d, "Statement", "__pf_absent")
	is_array(arr)
	out := [[i, s] | some i, s in arr]
}

_pf_ief_pairs := {["Action", "NotAction"], ["Resource", "NotResource"]}

violation contains make_diag_full("pf-iam-policy-exclusive-fields", "ERROR", name,
	sprintf("%s.Statement.%d.%s", [path, i, pair[1]]),
	sprintf("Statement sets both %s and %s; the policy is rejected with \"Syntax errors in policy.\"", [pair[0], pair[1]]),
	"Keep one of the pair per statement",
	"https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements.html") if {
	some [name, path, d] in _pf_ief_docs
	some [i, s] in _pf_ief_stmts(d)
	is_object(s)
	some pair in _pf_ief_pairs
	object.get(s, pair[0], "__pf_absent") != "__pf_absent"
	object.get(s, pair[1], "__pf_absent") != "__pf_absent"
}
