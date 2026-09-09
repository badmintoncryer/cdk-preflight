package cdk_preflight

import rego.v1

_pf_cf_rhp_xss_protection_report_uri_requires_protection_fix := "Set Protection to true, or drop ReportUri"

_pf_cf_rhp_xss_protection_report_uri_requires_protection_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudfront-responseheaderspolicy.html"

violation contains make_diag_full("pf-cloudfront-rhp-xss-protection-report-uri-requires-protection", "ERROR", name, "Properties.ResponseHeadersPolicyConfig.SecurityHeadersConfig.XSSProtection",
	"ReportUri can only be set when Protection is true",
	_pf_cf_rhp_xss_protection_report_uri_requires_protection_fix, _pf_cf_rhp_xss_protection_report_uri_requires_protection_url) if {
	some name in resources_of_type("AWS::CloudFront::ResponseHeadersPolicy")
	cfgv := _pf_cflib_props(name, "ResponseHeadersPolicyConfig")
	sh := object.get(cfgv, "SecurityHeadersConfig", null)
	is_object(sh)
	xs := object.get(sh, "XSSProtection", null)
	is_object(xs)
	object.get(xs, "ReportUri", "__pf_absent") != "__pf_absent"
	object.get(xs, "Protection", false) == false
}
