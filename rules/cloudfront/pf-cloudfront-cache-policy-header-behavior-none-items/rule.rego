package cdk_preflight

import rego.v1

_pf_cf_cache_policy_header_behavior_none_items_fix := "Remove Headers, or change HeaderBehavior"

_pf_cf_cache_policy_header_behavior_none_items_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudfront-cachepolicy.html"

violation contains make_diag_full("pf-cloudfront-cache-policy-header-behavior-none-items", "ERROR", name, "Properties.CachePolicyConfig.ParametersInCacheKeyAndForwardedToOrigin.HeadersConfig",
	sprintf("HeaderBehavior %v cannot be combined with Headers", [bh]),
	_pf_cf_cache_policy_header_behavior_none_items_fix, _pf_cf_cache_policy_header_behavior_none_items_url) if {
	some name in resources_of_type("AWS::CloudFront::CachePolicy")
	pk := object.get(_pf_cflib_props(name, "CachePolicyConfig"), "ParametersInCacheKeyAndForwardedToOrigin", null)
	is_object(pk)
	sc := object.get(pk, "HeadersConfig", null)
	is_object(sc)
	bh := object.get(sc, "HeaderBehavior", null)
	bh in {"none"}
	count(object.get(sc, "Headers", [])) > 0
}
