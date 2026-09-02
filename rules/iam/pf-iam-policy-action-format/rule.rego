package cdk_preflight

import rego.v1

# A bare action name has no service to attach to. Intrinsics inside the
# preprocessed document are marker objects, so is_string mutes them.
_pf_iaf_docs contains [name, path, d] if {
	some name in resources_of_type("AWS::IAM::Role")
	some p in flatten_list(name, "Properties.Policies")
	is_object(p.value)
	d := object.get(p.value, "PolicyDocument", {})
	is_object(d)
	path := sprintf("Properties.Policies.%d.PolicyDocument", [p.index])
}

_pf_iaf_docs contains [name, path, d] if {
	some t in {"AWS::IAM::Policy", "AWS::IAM::ManagedPolicy"}
	some name in resources_of_type(t)
	props := input.resources[name].properties
	is_object(props)
	d := object.get(props, "PolicyDocument", {})
	is_object(d)
	path := "Properties.PolicyDocument"
}

_pf_iaf_stmts(d) := [[0, s]] if {
	s := object.get(d, "Statement", "__pf_absent")
	is_object(s)
}

_pf_iaf_stmts(d) := out if {
	arr := object.get(d, "Statement", "__pf_absent")
	is_array(arr)
	out := [[i, s] | some i, s in arr]
}

_pf_iaf_vals(v) := [v] if is_string(v)

_pf_iaf_vals(v) := v if is_array(v)

violation contains make_diag_full("pf-iam-policy-action-format", "ERROR", name,
	sprintf("%s.Statement.%d.Action", [path, i]),
	sprintf("Action '%s' has no service prefix; the policy is rejected with \"Actions/Conditions must be prefaced by a vendor, e.g., iam, sdb, ec2, etc.\"", [a]),
	"Write actions as service:Action (e.g. s3:GetObject), or *",
	"https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements.html") if {
	some [name, path, d] in _pf_iaf_docs
	some [i, s] in _pf_iaf_stmts(d)
	is_object(s)
	some a in _pf_iaf_vals(object.get(s, "Action", []))
	is_string(a)
	a != "*"
	not contains(a, ":")
}
