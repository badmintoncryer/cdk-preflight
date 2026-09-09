package cdk_preflight

import rego.v1

_pf_cf_origin_shield_region_required_fix := "Set OriginShieldRegion to the region closest to the origin"

_pf_cf_origin_shield_region_required_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cloudfront-distribution-origin.html"

violation contains make_diag_full("pf-cloudfront-origin-shield-region-required", "ERROR", name, o.path,
	"OriginShield is enabled but OriginShieldRegion is not set",
	_pf_cf_origin_shield_region_required_fix, _pf_cf_origin_shield_region_required_url) if {
	some name in resources_of_type("AWS::CloudFront::Distribution")
	some o in _pf_cflib_origins(name)
	os := object.get(o.value, "OriginShield", null)
	is_object(os)
	object.get(os, "Enabled", false) == true
	object.get(os, "OriginShieldRegion", "__pf_absent") == "__pf_absent"
}
