package cdk_preflight

import rego.v1

_pf_cf_cache_policy_or_forwarded_values_required_fix := "Attach a cache policy with CachePolicyId"

_pf_cf_cache_policy_or_forwarded_values_required_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cloudfront-distribution-cachebehavior.html"

violation contains make_diag_full("pf-cloudfront-cache-policy-or-forwarded-values-required", "ERROR", name, b.path,
	"a cache behavior must include either CachePolicyId or ForwardedValues",
	_pf_cf_cache_policy_or_forwarded_values_required_fix, _pf_cf_cache_policy_or_forwarded_values_required_url) if {
	some name in resources_of_type("AWS::CloudFront::Distribution")
	some b in _pf_cflib_behaviors(name)
	is_object(b.value)
	object.get(b.value, "CachePolicyId", "__pf_absent") == "__pf_absent"
	object.get(b.value, "ForwardedValues", "__pf_absent") == "__pf_absent"
}
