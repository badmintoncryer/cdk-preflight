package cdk_preflight

import rego.v1

# Only literal strings are judged - Fn::GetAtt / Fn::Sub values surface
# as marker objects in the preprocessed document (measured), so the
# is_string guard mutes them.
_pf_irf_docs contains [name, path, d] if {
	some name in resources_of_type("AWS::IAM::Role")
	some p in flatten_list(name, "Properties.Policies")
	is_object(p.value)
	d := object.get(p.value, "PolicyDocument", {})
	is_object(d)
	path := sprintf("Properties.Policies.%d.PolicyDocument", [p.index])
}

_pf_irf_docs contains [name, path, d] if {
	some t in {"AWS::IAM::Policy", "AWS::IAM::ManagedPolicy"}
	some name in resources_of_type(t)
	props := input.resources[name].properties
	is_object(props)
	d := object.get(props, "PolicyDocument", {})
	is_object(d)
	path := "Properties.PolicyDocument"
}

_pf_irf_stmts(d) := [[0, s]] if {
	s := object.get(d, "Statement", "__pf_absent")
	is_object(s)
}

_pf_irf_stmts(d) := out if {
	arr := object.get(d, "Statement", "__pf_absent")
	is_array(arr)
	out := [[i, s] | some i, s in arr]
}

_pf_irf_vals(v) := [v] if is_string(v)

_pf_irf_vals(v) := v if is_array(v)

violation contains make_diag_full("pf-iam-policy-resource-format", "ERROR", name,
	sprintf("%s.Statement.%d.Resource", [path, i]),
	sprintf("Resource '%s' is not an ARN; the policy is rejected with \"Resource %s must be in ARN format or '*'.\"", [r, r]),
	"Use a full ARN (arn:...) or *",
	"https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements.html") if {
	some [name, path, d] in _pf_irf_docs
	some [i, s] in _pf_irf_stmts(d)
	is_object(s)
	some r in _pf_irf_vals(object.get(s, "Resource", []))
	is_string(r)
	r != "*"
	not startswith(r, "arn:")
}
