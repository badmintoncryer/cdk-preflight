package cdk_preflight

import rego.v1

_pf_sidfmt_docs contains [name, path, d] if {
	some t in {"AWS::IAM::Role", "AWS::IAM::User", "AWS::IAM::Group"}
	some name in resources_of_type(t)
	some p in flatten_list(name, "Properties.Policies")
	is_object(p.value)
	d := object.get(p.value, "PolicyDocument", {})
	is_object(d)
	path := sprintf("Properties.Policies.%d.PolicyDocument", [p.index])
}

_pf_sidfmt_docs contains [name, path, d] if {
	some name in resources_of_type("AWS::IAM::Role")
	props := input.resources[name].properties
	is_object(props)
	d := object.get(props, "AssumeRolePolicyDocument", {})
	is_object(d)
	path := "Properties.AssumeRolePolicyDocument"
}

_pf_sidfmt_docs contains [name, path, d] if {
	some t in {"AWS::IAM::Policy", "AWS::IAM::ManagedPolicy"}
	some name in resources_of_type(t)
	props := input.resources[name].properties
	is_object(props)
	d := object.get(props, "PolicyDocument", {})
	is_object(d)
	path := "Properties.PolicyDocument"
}

_pf_sidfmt_stmts(d) := [[0, s]] if {
	s := object.get(d, "Statement", "__pf_absent")
	is_object(s)
}

_pf_sidfmt_stmts(d) := out if {
	arr := object.get(d, "Statement", "__pf_absent")
	is_array(arr)
	out := [[i, s] | some i, s in arr]
}

violation contains make_diag_full("pf-iam-policy-sid-format", "ERROR", name,
	sprintf("%s.Statement.%d.Sid", [path, i]),
	sprintf("Sid '%s' is not alphanumeric; IAM rejects the policy with \"Statement IDs (SID) must be alpha-numeric\"", [sid]),
	"Use only letters and digits in the Sid (drop hyphens, underscores and spaces)",
	"https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_sid.html") if {
	some [name, path, d] in _pf_sidfmt_docs
	some [i, s] in _pf_sidfmt_stmts(d)
	is_object(s)
	sid := object.get(s, "Sid", null)
	is_string(sid)
	not regex.match(`^[0-9A-Za-z]*$`, sid)
}
