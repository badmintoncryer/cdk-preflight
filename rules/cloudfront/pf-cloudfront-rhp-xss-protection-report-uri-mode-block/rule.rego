package cdk_preflight

import rego.v1

_pf_cf_rhp_xss_protection_report_uri_mode_block_fix := "Keep either ReportUri or ModeBlock, not both"

_pf_cf_rhp_xss_protection_report_uri_mode_block_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudfront-responseheaderspolicy.html"

violation contains make_diag_full("pf-cloudfront-rhp-xss-protection-report-uri-mode-block", "ERROR", name, "Properties.ResponseHeadersPolicyConfig.SecurityHeadersConfig.XSSProtection",
	"XSSProtection accepts ModeBlock or ReportUri, but not both",
	_pf_cf_rhp_xss_protection_report_uri_mode_block_fix, _pf_cf_rhp_xss_protection_report_uri_mode_block_url) if {
	some name in resources_of_type("AWS::CloudFront::ResponseHeadersPolicy")
	cfgv := _pf_cflib_props(name, "ResponseHeadersPolicyConfig")
	sh := object.get(cfgv, "SecurityHeadersConfig", null)
	is_object(sh)
	xs := object.get(sh, "XSSProtection", null)
	is_object(xs)
	object.get(xs, "ReportUri", "__pf_absent") != "__pf_absent"
	object.get(xs, "ModeBlock", false) == true
}
