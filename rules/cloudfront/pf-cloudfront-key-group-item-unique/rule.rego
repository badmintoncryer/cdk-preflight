package cdk_preflight

import rego.v1

_pf_cf_key_group_item_unique_fix := "List each public key id once"

_pf_cf_key_group_item_unique_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudfront-keygroup.html"

violation contains make_diag_full("pf-cloudfront-key-group-item-unique", "ERROR", name, "Properties.KeyGroupConfig",
	sprintf("public key %v is listed more than once", [k]),
	_pf_cf_key_group_item_unique_fix, _pf_cf_key_group_item_unique_url) if {
	some name in resources_of_type("AWS::CloudFront::KeyGroup")
	cfgv := _pf_cflib_props(name, "KeyGroupConfig")
	its := [i | some i in object.get(cfgv, "Items", []); is_string(i)]
	some k in its
	count([x | some x in its; x == k]) > 1
}
