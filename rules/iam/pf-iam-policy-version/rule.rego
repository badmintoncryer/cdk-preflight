package cdk_preflight

import rego.v1

# The version string is an enum of two dates; anything else is a syntax
# error at create. Measured 2026-11-25 (us-east-1): an inline policy on a role
# and AWS::IAM::Policy take an omitted Version (it defaults to 2008-10-17) and
# 2008-10-17, but AWS::IAM::ManagedPolicy rejects both with "Policy document
# must be version 2012-10-17 or greater."
_pf_ipv_docs contains [name, path, d] if {
	some name in resources_of_type("AWS::IAM::Role")
	some p in flatten_list(name, "Properties.Policies")
	is_object(p.value)
	d := object.get(p.value, "PolicyDocument", {})
	is_object(d)
	path := sprintf("Properties.Policies.%d.PolicyDocument", [p.index])
}

_pf_ipv_docs contains [name, "Properties.PolicyDocument", d] if {
	some name in resources_of_type("AWS::IAM::Policy")
	d := _pf_ipv_doc(name)
}

_pf_ipv_doc(name) := d if {
	props := input.resources[name].properties
	is_object(props)
	d := object.get(props, "PolicyDocument", {})
	is_object(d)
}

violation contains make_diag_full("pf-iam-policy-version", "ERROR", name,
	sprintf("%s.Version", [path]),
	sprintf("Policy Version '%s' does not exist; the policy is rejected with \"Syntax errors in policy.\"", [v]),
	"Use Version: 2012-10-17",
	"https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_version.html") if {
	some [name, path, d] in _pf_ipv_docs
	v := d.Version
	is_string(v)
	not v in {"2012-10-17", "2008-10-17"}
}

violation contains make_diag_full("pf-iam-policy-version", "ERROR", name,
	"Properties.PolicyDocument.Version",
	sprintf("A managed policy needs Version 2012-10-17, but it is %s; CreatePolicy fails with \"Policy document must be version 2012-10-17 or greater.\"", [shown]),
	"Use Version: 2012-10-17",
	"https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_version.html") if {
	some name in resources_of_type("AWS::IAM::ManagedPolicy")
	d := _pf_ipv_doc(name)
	shown := _pf_ipv_managed_bad(d)
}

_pf_ipv_managed_bad(d) := "missing" if not "Version" in object.keys(d)

_pf_ipv_managed_bad(d) := sprintf("'%s'", [v]) if {
	v := d.Version
	is_string(v)
	v != "2012-10-17"
}
