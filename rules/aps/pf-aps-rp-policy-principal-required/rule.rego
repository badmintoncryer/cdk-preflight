package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-aps-rp-policy-principal-required", "ERROR", name,
	"Properties.PolicyDocument",
	"a statement has no Principal; PutResourcePolicy fails with \"Resource policy cannot contain invalid arguments\"",
	"Name the trusted account or role in Principal on every statement",
	"https://docs.aws.amazon.com/prometheus/latest/userguide/security_iam_service-with-iam.html") if {
	some name in resources_of_type("AWS::APS::ResourcePolicy")
	some s in _pf_aps_policy_statements(name)
	object.get(s, "Principal", "__pf_absent") == "__pf_absent"
}
