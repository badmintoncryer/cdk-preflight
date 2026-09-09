package cdk_preflight

import rego.v1

_pf_cf_cache_policy_query_string_behavior_items_fix := "List at least one entry in QueryStrings"

_pf_cf_cache_policy_query_string_behavior_items_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudfront-cachepolicy.html"

violation contains make_diag_full("pf-cloudfront-cache-policy-query-string-behavior-items", "ERROR", name, "Properties.CachePolicyConfig.ParametersInCacheKeyAndForwardedToOrigin.QueryStringsConfig",
	sprintf("QueryStringBehavior %v requires at least one entry in QueryStrings", [bh]),
	_pf_cf_cache_policy_query_string_behavior_items_fix, _pf_cf_cache_policy_query_string_behavior_items_url) if {
	some name in resources_of_type("AWS::CloudFront::CachePolicy")
	pk := object.get(_pf_cflib_props(name, "CachePolicyConfig"), "ParametersInCacheKeyAndForwardedToOrigin", null)
	is_object(pk)
	sc := object.get(pk, "QueryStringsConfig", null)
	is_object(sc)
	bh := object.get(sc, "QueryStringBehavior", null)
	bh in {"whitelist", "allExcept"}
	count(object.get(sc, "QueryStrings", [])) == 0
}
