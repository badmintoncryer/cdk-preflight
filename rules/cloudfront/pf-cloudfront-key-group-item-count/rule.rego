package cdk_preflight

import rego.v1

_pf_cf_key_group_item_count_fix := "Split the keys across multiple key groups"

_pf_cf_key_group_item_count_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudfront-keygroup.html"

violation contains make_diag_full("pf-cloudfront-key-group-item-count", "ERROR", name, "Properties.KeyGroupConfig",
	sprintf("the key group lists %v public keys; the limit is 5", [count(its)]),
	_pf_cf_key_group_item_count_fix, _pf_cf_key_group_item_count_url) if {
	some name in resources_of_type("AWS::CloudFront::KeyGroup")
	cfgv := _pf_cflib_props(name, "KeyGroupConfig")
	its := object.get(cfgv, "Items", [])
	count(its) > 5
}
