package cdk_preflight

import rego.v1

_pf_inline_policy_limits := {
	"AWS::IAM::Policy": 10240,
	"AWS::IAM::RolePolicy": 10240,
	"AWS::IAM::UserPolicy": 2048,
	"AWS::IAM::GroupPolicy": 5120,
}

violation contains make_diag_full("pf-iam-inline-policy-size", "ERROR", name,
	"Properties.PolicyDocument",
	sprintf("PolicyDocument is %d characters (JSON without whitespace) but the inline policy limit for %s is %d (role: 10240, group: 5120, user: 2048)", [size, rtype, limit]),
	"Move statements into managed policies or shorten the document",
	"https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_iam-quotas.html") if {
	some rtype, limit in _pf_inline_policy_limits
	some name in resources_of_type(rtype)
	doc := resolve(name, "Properties.PolicyDocument")
	is_object(doc)
	size := count(json.marshal(doc))
	size > limit
}
