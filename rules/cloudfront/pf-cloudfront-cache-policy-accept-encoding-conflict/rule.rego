package cdk_preflight

import rego.v1

_pf_cf_cache_policy_accept_encoding_conflict_fix := "Drop Accept-Encoding from Headers, or turn off EnableAcceptEncodingGzip / EnableAcceptEncodingBrotli"

_pf_cf_cache_policy_accept_encoding_conflict_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudfront-cachepolicy.html"

violation contains make_diag_full("pf-cloudfront-cache-policy-accept-encoding-conflict", "ERROR", name, "Properties.CachePolicyConfig.ParametersInCacheKeyAndForwardedToOrigin",
	sprintf("%v cannot be true while the Accept-Encoding header is in the cache key", [k]),
	_pf_cf_cache_policy_accept_encoding_conflict_fix, _pf_cf_cache_policy_accept_encoding_conflict_url) if {
	some name in resources_of_type("AWS::CloudFront::CachePolicy")
	pk := object.get(_pf_cflib_props(name, "CachePolicyConfig"), "ParametersInCacheKeyAndForwardedToOrigin", null)
	is_object(pk)
	some k in ["EnableAcceptEncodingGzip", "EnableAcceptEncodingBrotli"]
	object.get(pk, k, false) == true
	hc := object.get(pk, "HeadersConfig", null)
	is_object(hc)
	some h in object.get(hc, "Headers", [])
	is_string(h)
	lower(h) == "accept-encoding"
}
