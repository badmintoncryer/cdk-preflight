package cdk_preflight

import rego.v1

_pf_cf_cache_behavior_target_origin_exists_fix := "Set TargetOriginId to one of the Origins[].Id or OriginGroups.Items[].Id values"

_pf_cf_cache_behavior_target_origin_exists_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cloudfront-distribution-distributionconfig.html"

violation contains make_diag_full("pf-cloudfront-cache-behavior-target-origin-exists", "ERROR", name, b.path,
	sprintf("TargetOriginId %v does not match any origin or origin group Id %v", [tid, ids]),
	_pf_cf_cache_behavior_target_origin_exists_fix, _pf_cf_cache_behavior_target_origin_exists_url) if {
	some name in resources_of_type("AWS::CloudFront::Distribution")
	some b in _pf_cflib_behaviors(name)
	tid := object.get(b.value, "TargetOriginId", null)
	is_string(tid)
	ids := _pf_cflib_origin_ids(name)
	count(ids) > 0
	not tid in ids
}
