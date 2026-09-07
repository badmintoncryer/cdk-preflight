package cdk_preflight

import rego.v1

# "Provided registry policy is invalid: Missing required field Version."
# Measured 2026-09-07, schemas:PutResourcePolicy, us-east-1. The policy is
# skipped when it is an unresolvable intrinsic (marker keys start with __).
_pf_schpol_plain(p) if {
	is_object(p)
	every k, _ in p {
		not startswith(k, "__")
	}
}

violation contains make_diag_full("pf-eventschemas-registry-policy", "ERROR", name,
	"Properties.Policy",
	"The registry policy has no Version; PutResourcePolicy fails with \"Provided registry policy is invalid: Missing required field Version\"",
	"Add \"Version\": \"2012-10-17\" to the policy document",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eventschemas-registrypolicy.html") if {
	some name in resources_of_type("AWS::EventSchemas::RegistryPolicy")
	p := input.resources[name].properties.Policy
	_pf_schpol_plain(p)
	object.get(p, "Version", "__pf_absent") == "__pf_absent"
}
