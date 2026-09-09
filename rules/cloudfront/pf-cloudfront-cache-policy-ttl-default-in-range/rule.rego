package cdk_preflight

import rego.v1

_pf_cf_cache_policy_ttl_default_in_range_fix := "Order the TTLs as MinTTL <= DefaultTTL <= MaxTTL"

_pf_cf_cache_policy_ttl_default_in_range_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudfront-cachepolicy.html"

violation contains make_diag_full("pf-cloudfront-cache-policy-ttl-default-in-range", "ERROR", name, "Properties.CachePolicyConfig",
	sprintf("DefaultTTL (%v) is below MinTTL (%v)", [df, mn]),
	_pf_cf_cache_policy_ttl_default_in_range_fix, _pf_cf_cache_policy_ttl_default_in_range_url) if {
	some name in resources_of_type("AWS::CloudFront::CachePolicy")
	cfgv := _pf_cflib_props(name, "CachePolicyConfig")
	mn := to_number(object.get(cfgv, "MinTTL", null))
	df := to_number(object.get(cfgv, "DefaultTTL", null))
	df < mn
}

violation contains make_diag_full("pf-cloudfront-cache-policy-ttl-default-in-range", "ERROR", name, "Properties.CachePolicyConfig",
	sprintf("DefaultTTL (%v) is above MaxTTL (%v)", [df, mx]),
	_pf_cf_cache_policy_ttl_default_in_range_fix, _pf_cf_cache_policy_ttl_default_in_range_url) if {
	some name in resources_of_type("AWS::CloudFront::CachePolicy")
	cfgv := _pf_cflib_props(name, "CachePolicyConfig")
	mx := to_number(object.get(cfgv, "MaxTTL", null))
	df := to_number(object.get(cfgv, "DefaultTTL", null))
	df > mx
}
