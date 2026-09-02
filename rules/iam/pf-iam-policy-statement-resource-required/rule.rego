package cdk_preflight

import rego.v1

# A statement scoped to nothing is rejected.
_pf_isrr_docs contains [name, path, d] if {
	some name in resources_of_type("AWS::IAM::Role")
	some p in flatten_list(name, "Properties.Policies")
	is_object(p.value)
	d := object.get(p.value, "PolicyDocument", {})
	is_object(d)
	path := sprintf("Properties.Policies.%d.PolicyDocument", [p.index])
}

_pf_isrr_docs contains [name, path, d] if {
	some t in {"AWS::IAM::Policy", "AWS::IAM::ManagedPolicy"}
	some name in resources_of_type(t)
	props := input.resources[name].properties
	is_object(props)
	d := object.get(props, "PolicyDocument", {})
	is_object(d)
	path := "Properties.PolicyDocument"
}

_pf_isrr_stmts(d) := [[0, s]] if {
	s := object.get(d, "Statement", "__pf_absent")
	is_object(s)
}

_pf_isrr_stmts(d) := out if {
	arr := object.get(d, "Statement", "__pf_absent")
	is_array(arr)
	out := [[i, s] | some i, s in arr]
}

violation contains make_diag_full("pf-iam-policy-statement-resource-required", "ERROR", name,
	sprintf("%s.Statement.%d", [path, i]),
	"Statement has neither Resource nor NotResource; the policy is rejected with \"Policy statement must contain resources.\"",
	"Add Resource (an ARN or *) to the statement",
	"https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements.html") if {
	some [name, path, d] in _pf_isrr_docs
	some [i, s] in _pf_isrr_stmts(d)
	is_object(s)
	object.get(s, "Resource", "__pf_absent") == "__pf_absent"
	object.get(s, "NotResource", "__pf_absent") == "__pf_absent"
}
