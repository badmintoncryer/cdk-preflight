package cdk_preflight

import rego.v1

# Only an exact repeat conflicts. An overlap does not: with collection/probe-e
# live, collection/probe* was ACCEPTED (2026-09-25, us-east-1), so comparing
# prefixes here would be a false positive.

violation contains make_diag_full("pf-aoss-encryption-policy-duplicate-resource", "ERROR", n2,
	"Properties.Policy.Rules",
	sprintf("resource pattern %v is already claimed by encryption policy %v in this template; CreateSecurityPolicy answers \"Given encryption policy is conflicting with the existing encryption policies\"", [res, n1]),
	"Give each encryption policy a disjoint set of resource patterns, or merge the two policies into one",
	"https://docs.aws.amazon.com/opensearch-service/latest/developerguide/serverless-encryption.html") if {
	some n1 in _pf_aoss_enc
	some n2 in _pf_aoss_enc
	n1 < n2
	some res in _pf_aoss_resource_set(n1)
	res in _pf_aoss_resource_set(n2)
}
