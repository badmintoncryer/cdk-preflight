package cdk_preflight

import rego.v1

# Lowercase effects are a classic hand-written-JSON typo the schema
# cannot see (the document is opaque json).
_pf_iec_docs contains [name, path, d] if {
	some name in resources_of_type("AWS::IAM::Role")
	some p in flatten_list(name, "Properties.Policies")
	is_object(p.value)
	d := object.get(p.value, "PolicyDocument", {})
	is_object(d)
	path := sprintf("Properties.Policies.%d.PolicyDocument", [p.index])
}

_pf_iec_docs contains [name, path, d] if {
	some t in {"AWS::IAM::Policy", "AWS::IAM::ManagedPolicy"}
	some name in resources_of_type(t)
	props := input.resources[name].properties
	is_object(props)
	d := object.get(props, "PolicyDocument", {})
	is_object(d)
	path := "Properties.PolicyDocument"
}

_pf_iec_stmts(d) := [[0, s]] if {
	s := object.get(d, "Statement", "__pf_absent")
	is_object(s)
}

_pf_iec_stmts(d) := out if {
	arr := object.get(d, "Statement", "__pf_absent")
	is_array(arr)
	out := [[i, s] | some i, s in arr]
}

violation contains make_diag_full("pf-iam-policy-effect-case", "ERROR", name,
	sprintf("%s.Statement.%d.Effect", [path, i]),
	sprintf("Effect '%s' is not Allow or Deny (case-sensitive); the policy is rejected with \"The policy failed legacy parsing\"", [ef]),
	"Use Effect: Allow or Effect: Deny",
	"https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements.html") if {
	some [name, path, d] in _pf_iec_docs
	some [i, s] in _pf_iec_stmts(d)
	is_object(s)
	ef := object.get(s, "Effect", "__pf_absent")
	is_string(ef)
	not ef in {"Allow", "Deny"}
}
