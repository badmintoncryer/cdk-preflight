package cdk_preflight

import rego.v1

# The Regions listed in the CloudFront developer guide (origin-shield.html, read
# 2026-11-25). eu-west-3 was missing and was flagged although it deploys.

_pf_cf_origin_shield_region_supported_fix := "Pick one of the 14 regions where Origin Shield is available"

_pf_cf_origin_shield_region_supported_url := "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/origin-shield.html"

violation contains make_diag_full("pf-cloudfront-origin-shield-region-supported", "ERROR", name, o.path,
	sprintf("Origin Shield is not offered in %v", [r]),
	_pf_cf_origin_shield_region_supported_fix, _pf_cf_origin_shield_region_supported_url) if {
	some name in resources_of_type("AWS::CloudFront::Distribution")
	some o in _pf_cflib_origins(name)
	os := object.get(o.value, "OriginShield", null)
	is_object(os)
	r := object.get(os, "OriginShieldRegion", null)
	is_string(r)
	not r in {"us-east-1", "us-east-2", "us-west-2", "ap-south-1", "ap-northeast-1", "ap-northeast-2", "ap-southeast-1", "ap-southeast-2", "eu-central-1", "eu-west-1", "eu-west-2", "eu-west-3", "sa-east-1", "me-central-1"}
}
