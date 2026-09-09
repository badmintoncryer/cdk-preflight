package cdk_preflight

import rego.v1

_pf_cf_rhp_custom_header_unique_fix := "Declare each response header once"

_pf_cf_rhp_custom_header_unique_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudfront-responseheaderspolicy.html"

violation contains make_diag_full("pf-cloudfront-rhp-custom-header-unique", "ERROR", name, "Properties.ResponseHeadersPolicyConfig.CustomHeadersConfig",
	sprintf("header %v is declared more than once", [k]),
	_pf_cf_rhp_custom_header_unique_fix, _pf_cf_rhp_custom_header_unique_url) if {
	some name in resources_of_type("AWS::CloudFront::ResponseHeadersPolicy")
	cfgv := _pf_cflib_props(name, "ResponseHeadersPolicyConfig")
	chc := object.get(cfgv, "CustomHeadersConfig", null)
	is_object(chc)
	ns := [lower(h) | some it in object.get(chc, "Items", []); h := object.get(it, "Header", null); is_string(h)]
	some k in ns
	count([x | some x in ns; x == k]) > 1
}
