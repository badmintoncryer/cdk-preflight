package cdk_preflight

import rego.v1

_pf_cf_ttl_fix := "Order the TTLs as MinTTL <= DefaultTTL <= MaxTTL"

_pf_cf_ttl_url := "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/Expiration.html"

_pf_cf_behaviors(name) := pfv if {
	_pf_static_list(name, "Properties.DistributionConfig.DefaultCacheBehavior")
	_pf_static_list(name, "Properties.DistributionConfig.CacheBehaviors")
	pfv := array.concat(
	[{"path": "Properties.DistributionConfig.DefaultCacheBehavior", "value": it.value} |
		some it in flatten_list(name, "Properties.DistributionConfig.DefaultCacheBehavior")],
	[{"path": sprintf("Properties.DistributionConfig.CacheBehaviors.%d", [it.index]), "value": it.value} |
		some it in flatten_list(name, "Properties.DistributionConfig.CacheBehaviors")],
)
}

violation contains make_diag_full("pf-cloudfront-ttl-order", "ERROR", name, b.path,
	sprintf("MinTTL (%v) must be less than or equal to MaxTTL (%v)", [mn, mx]),
	_pf_cf_ttl_fix, _pf_cf_ttl_url) if {
	some name in resources_of_type("AWS::CloudFront::Distribution")
	some b in _pf_cf_behaviors(name)
	is_object(b.value)
	mn := to_number(b.value["MinTTL"])
	mx := to_number(b.value["MaxTTL"])
	mn > mx
}

violation contains make_diag_full("pf-cloudfront-ttl-order", "ERROR", name, b.path,
	sprintf("MinTTL (%v) must be less than or equal to DefaultTTL (%v)", [mn, df]),
	_pf_cf_ttl_fix, _pf_cf_ttl_url) if {
	some name in resources_of_type("AWS::CloudFront::Distribution")
	some b in _pf_cf_behaviors(name)
	is_object(b.value)
	mn := to_number(b.value["MinTTL"])
	df := to_number(b.value["DefaultTTL"])
	mn > df
}

violation contains make_diag_full("pf-cloudfront-ttl-order", "ERROR", name, b.path,
	sprintf("DefaultTTL (%v) must be less than or equal to MaxTTL (%v)", [df, mx]),
	_pf_cf_ttl_fix, _pf_cf_ttl_url) if {
	some name in resources_of_type("AWS::CloudFront::Distribution")
	some b in _pf_cf_behaviors(name)
	is_object(b.value)
	df := to_number(b.value["DefaultTTL"])
	mx := to_number(b.value["MaxTTL"])
	df > mx
}
