package cdk_preflight

import rego.v1

# Shape check only: every service principal ends in .amazonaws.com (or
# .amazonaws.com.cn in the China partition). Whether a well-shaped name
# exists is left to the service.
_pf_itsp_trust(name) := d if {
	props := input.resources[name].properties
	is_object(props)
	d := object.get(props, "AssumeRolePolicyDocument", "__pf_absent")
	is_object(d)
}

_pf_itsp_stmts(d) := [[0, s]] if {
	s := object.get(d, "Statement", "__pf_absent")
	is_object(s)
}

_pf_itsp_stmts(d) := out if {
	arr := object.get(d, "Statement", "__pf_absent")
	is_array(arr)
	out := [[i, s] | some i, s in arr]
}

_pf_itsp_vals(v) := [v] if is_string(v)

_pf_itsp_vals(v) := v if is_array(v)

_pf_itsp_ok(sp) if endswith(sp, ".amazonaws.com")

_pf_itsp_ok(sp) if endswith(sp, ".amazonaws.com.cn")

violation contains make_diag_full("pf-iam-trust-policy-service-principal", "ERROR", name,
	sprintf("Properties.AssumeRolePolicyDocument.Statement.%d.Principal.Service", [i]),
	sprintf("Service principal '%s' is not an amazonaws.com domain; the role create fails with 'Invalid principal in policy: \"SERVICE\":\"%s\"'", [sp, sp]),
	"Use the service principal name, e.g. lambda.amazonaws.com",
	"https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html") if {
	some name in resources_of_type("AWS::IAM::Role")
	d := _pf_itsp_trust(name)
	some [i, s] in _pf_itsp_stmts(d)
	is_object(s)
	p := object.get(s, "Principal", {})
	is_object(p)
	some sp in _pf_itsp_vals(object.get(p, "Service", []))
	is_string(sp)
	not _pf_itsp_ok(sp)
}
