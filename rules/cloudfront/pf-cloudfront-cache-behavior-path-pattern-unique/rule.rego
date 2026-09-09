package cdk_preflight

import rego.v1

_pf_cf_cache_behavior_path_pattern_unique_fix := "Give each cache behavior a distinct PathPattern"

_pf_cf_cache_behavior_path_pattern_unique_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cloudfront-distribution-distributionconfig.html"

violation contains make_diag_full("pf-cloudfront-cache-behavior-path-pattern-unique", "ERROR", name, "Properties.DistributionConfig.CacheBehaviors",
	sprintf("PathPattern %v is used by more than one cache behavior", [k]),
	_pf_cf_cache_behavior_path_pattern_unique_fix, _pf_cf_cache_behavior_path_pattern_unique_url) if {
	some name in resources_of_type("AWS::CloudFront::Distribution")
	pats := [pp | some it in flatten_list(name, "Properties.DistributionConfig.CacheBehaviors"); pp := object.get(it.value, "PathPattern", null); is_string(pp)]
	some k in pats
	count([x | some x in pats; x == k]) > 1
}
