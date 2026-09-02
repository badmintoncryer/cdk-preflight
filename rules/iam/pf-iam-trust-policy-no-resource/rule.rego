package cdk_preflight

import rego.v1

# The role itself is the resource of its trust policy; an explicit
# Resource field is prohibited.
_pf_itnr_trust(name) := d if {
	props := input.resources[name].properties
	is_object(props)
	d := object.get(props, "AssumeRolePolicyDocument", "__pf_absent")
	is_object(d)
}

_pf_itnr_stmts(d) := [[0, s]] if {
	s := object.get(d, "Statement", "__pf_absent")
	is_object(s)
}

_pf_itnr_stmts(d) := out if {
	arr := object.get(d, "Statement", "__pf_absent")
	is_array(arr)
	out := [[i, s] | some i, s in arr]
}

violation contains make_diag_full("pf-iam-trust-policy-no-resource", "ERROR", name,
	sprintf("Properties.AssumeRolePolicyDocument.Statement.%d.Resource", [i]),
	"Trust policy statement has a Resource field; the role create fails with \"Has prohibited field Resource\"",
	"Remove Resource from the trust policy statement",
	"https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements.html") if {
	some name in resources_of_type("AWS::IAM::Role")
	d := _pf_itnr_trust(name)
	some [i, s] in _pf_itnr_stmts(d)
	is_object(s)
	object.get(s, "Resource", "__pf_absent") != "__pf_absent"
}
