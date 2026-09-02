package cdk_preflight

import rego.v1

# The version string is an enum of two dates; anything else is a syntax
# error at create.
_pf_ipv_docs contains [name, path, d] if {
	some name in resources_of_type("AWS::IAM::Role")
	some p in flatten_list(name, "Properties.Policies")
	is_object(p.value)
	d := object.get(p.value, "PolicyDocument", {})
	is_object(d)
	path := sprintf("Properties.Policies.%d.PolicyDocument", [p.index])
}

_pf_ipv_docs contains [name, path, d] if {
	some t in {"AWS::IAM::Policy", "AWS::IAM::ManagedPolicy"}
	some name in resources_of_type(t)
	props := input.resources[name].properties
	is_object(props)
	d := object.get(props, "PolicyDocument", {})
	is_object(d)
	path := "Properties.PolicyDocument"
}

violation contains make_diag_full("pf-iam-policy-version", "ERROR", name,
	sprintf("%s.Version", [path]),
	sprintf("Policy Version '%s' does not exist; the policy is rejected with \"Syntax errors in policy.\"", [v]),
	"Use Version: 2012-10-17",
	"https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_version.html") if {
	some [name, path, d] in _pf_ipv_docs
	v := object.get(d, "Version", "__pf_absent")
	is_string(v)
	not v in {"2012-10-17", "2008-10-17"}
}
