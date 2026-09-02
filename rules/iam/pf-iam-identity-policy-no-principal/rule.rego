package cdk_preflight

import rego.v1

# Identity policies attach to their principal implicitly; the field
# belongs to resource-based policies.
_pf_iinp_docs contains [name, path, d] if {
	some name in resources_of_type("AWS::IAM::Role")
	some p in flatten_list(name, "Properties.Policies")
	is_object(p.value)
	d := object.get(p.value, "PolicyDocument", {})
	is_object(d)
	path := sprintf("Properties.Policies.%d.PolicyDocument", [p.index])
}

_pf_iinp_docs contains [name, path, d] if {
	some t in {"AWS::IAM::Policy", "AWS::IAM::ManagedPolicy"}
	some name in resources_of_type(t)
	props := input.resources[name].properties
	is_object(props)
	d := object.get(props, "PolicyDocument", {})
	is_object(d)
	path := "Properties.PolicyDocument"
}

_pf_iinp_stmts(d) := [[0, s]] if {
	s := object.get(d, "Statement", "__pf_absent")
	is_object(s)
}

_pf_iinp_stmts(d) := out if {
	arr := object.get(d, "Statement", "__pf_absent")
	is_array(arr)
	out := [[i, s] | some i, s in arr]
}

violation contains make_diag_full("pf-iam-identity-policy-no-principal", "ERROR", name,
	sprintf("%s.Statement.%d.Principal", [path, i]),
	"Identity policy statement has a Principal field; the policy is rejected with \"Policy document should not specify a principal.\"",
	"Remove Principal (identity policies apply to the identity they attach to)",
	"https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements.html") if {
	some [name, path, d] in _pf_iinp_docs
	some [i, s] in _pf_iinp_stmts(d)
	is_object(s)
	object.get(s, "Principal", "__pf_absent") != "__pf_absent"
}
