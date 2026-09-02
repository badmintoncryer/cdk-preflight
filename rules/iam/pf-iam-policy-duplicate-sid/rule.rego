package cdk_preflight

import rego.v1

# Pairwise uniqueness within one document; separate documents may reuse
# ids freely.
_pf_ids_docs contains [name, path, d] if {
	some name in resources_of_type("AWS::IAM::Role")
	some p in flatten_list(name, "Properties.Policies")
	is_object(p.value)
	d := object.get(p.value, "PolicyDocument", {})
	is_object(d)
	path := sprintf("Properties.Policies.%d.PolicyDocument", [p.index])
}

_pf_ids_docs contains [name, path, d] if {
	some t in {"AWS::IAM::Policy", "AWS::IAM::ManagedPolicy"}
	some name in resources_of_type(t)
	props := input.resources[name].properties
	is_object(props)
	d := object.get(props, "PolicyDocument", {})
	is_object(d)
	path := "Properties.PolicyDocument"
}

_pf_ids_stmts(d) := [[0, s]] if {
	s := object.get(d, "Statement", "__pf_absent")
	is_object(s)
}

_pf_ids_stmts(d) := out if {
	arr := object.get(d, "Statement", "__pf_absent")
	is_array(arr)
	out := [[i, s] | some i, s in arr]
}

violation contains make_diag_full("pf-iam-policy-duplicate-sid", "ERROR", name,
	sprintf("%s.Statement.%d.Sid", [path, j]),
	sprintf("Sid '%s' repeats within one policy; the policy is rejected with \"Statement IDs (SID) in a single policy must be unique.\"", [sid]),
	"Give every statement in the document a distinct Sid (or drop the duplicates)",
	"https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements.html") if {
	some [name, path, d] in _pf_ids_docs
	stmts := _pf_ids_stmts(d)
	some [i, a] in stmts
	some [j, b] in stmts
	i < j
	is_object(a)
	is_object(b)
	sid := object.get(a, "Sid", "__pf_absent")
	is_string(sid)
	sid == object.get(b, "Sid", "__pf_other")
}
