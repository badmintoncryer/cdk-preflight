package cdk_preflight

import rego.v1

_pf_cf_rhp_custom_header_blocklist_fix := "Remove the reserved header from CustomHeadersConfig"

_pf_cf_rhp_custom_header_blocklist_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudfront-responseheaderspolicy.html"

_pf_cf_rhp_custom_header_blocklist_names := {
	"connection",
	"content-encoding",
	"content-length",
	"expect",
	"host",
	"keep-alive",
	"proxy-authenticate",
	"proxy-authorization",
	"proxy-connection",
	"trailer",
	"transfer-encoding",
	"upgrade",
	"via",
	"warning",
	"x-accel-buffering",
	"x-accel-charset",
	"x-accel-limit-rate",
	"x-accel-redirect",
	"x-amzn-auth",
	"x-amzn-cf-billing",
	"x-amzn-cf-id",
	"x-amzn-cf-xff",
	"x-amzn-errortype",
	"x-amzn-fle-profile",
	"x-amzn-header-count",
	"x-amzn-header-order",
	"x-amzn-lambda-integration-tag",
	"x-amzn-requestid",
	"x-forwarded-proto",
	"x-real-ip",
}

violation contains make_diag_full("pf-cloudfront-rhp-custom-header-blocklist", "ERROR", name, "Properties.ResponseHeadersPolicyConfig.CustomHeadersConfig",
	sprintf("CustomHeaders contains %v, which CloudFront does not allow", [h]),
	_pf_cf_rhp_custom_header_blocklist_fix, _pf_cf_rhp_custom_header_blocklist_url) if {
	some name in resources_of_type("AWS::CloudFront::ResponseHeadersPolicy")
	cfgv := _pf_cflib_props(name, "ResponseHeadersPolicyConfig")
	chc := object.get(cfgv, "CustomHeadersConfig", null)
	is_object(chc)
	some it in object.get(chc, "Items", [])
	h := object.get(it, "Header", null)
	is_string(h)
	lower(h) in _pf_cf_rhp_custom_header_blocklist_names
}

violation contains make_diag_full("pf-cloudfront-rhp-custom-header-blocklist", "ERROR", name, "Properties.ResponseHeadersPolicyConfig.CustomHeadersConfig",
	sprintf("CustomHeaders contains %v, which CloudFront does not allow", [h]),
	_pf_cf_rhp_custom_header_blocklist_fix, _pf_cf_rhp_custom_header_blocklist_url) if {
	some name in resources_of_type("AWS::CloudFront::ResponseHeadersPolicy")
	cfgv := _pf_cflib_props(name, "ResponseHeadersPolicyConfig")
	chc := object.get(cfgv, "CustomHeadersConfig", null)
	is_object(chc)
	some it in object.get(chc, "Items", [])
	h := object.get(it, "Header", null)
	is_string(h)
	some p in ["x-amz-cf-","x-edge-"]
	startswith(lower(h), p)
}
