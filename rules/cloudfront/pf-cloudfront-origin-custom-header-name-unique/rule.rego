package cdk_preflight

import rego.v1

_pf_cf_origin_custom_header_name_unique_fix := "Declare each header name once"

_pf_cf_origin_custom_header_name_unique_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cloudfront-distribution-origin.html"

violation contains make_diag_full("pf-cloudfront-origin-custom-header-name-unique", "ERROR", name, o.path,
	sprintf("header name %v appears more than once in OriginCustomHeaders", [k]),
	_pf_cf_origin_custom_header_name_unique_fix, _pf_cf_origin_custom_header_name_unique_url) if {
	some name in resources_of_type("AWS::CloudFront::Distribution")
	some o in _pf_cflib_origins(name)
	ns := [lower(n) | some h in object.get(o.value, "OriginCustomHeaders", []); n := object.get(h, "HeaderName", null); is_string(n)]
	some k in ns
	count([x | some x in ns; x == k]) > 1
}
