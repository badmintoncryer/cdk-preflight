package cdk_preflight

import rego.v1

_pf_cf_origin_custom_header_blocklist_fix := "Remove the reserved header from OriginCustomHeaders"

_pf_cf_origin_custom_header_blocklist_url := "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/add-origin-custom-headers.html"

_pf_cf_origin_custom_header_blocklist_names := {
	"cache-control",
	"connection",
	"content-length",
	"cookie",
	"host",
	"if-match",
	"if-modified-since",
	"if-none-match",
	"if-range",
	"if-unmodified-since",
	"max-forwards",
	"pragma",
	"proxy-authenticate",
	"proxy-authorization",
	"proxy-connection",
	"range",
	"request-range",
	"te",
	"trailer",
	"transfer-encoding",
	"upgrade",
	"via",
	"x-real-ip",
}

violation contains make_diag_full("pf-cloudfront-origin-custom-header-blocklist", "ERROR", name, o.path,
	sprintf("CloudFront cannot add the reserved header %v to origin requests", [n]),
	_pf_cf_origin_custom_header_blocklist_fix, _pf_cf_origin_custom_header_blocklist_url) if {
	some name in resources_of_type("AWS::CloudFront::Distribution")
	some o in _pf_cflib_origins(name)
	some h in object.get(o.value, "OriginCustomHeaders", [])
	n := object.get(h, "HeaderName", null)
	is_string(n)
	lower(n) in _pf_cf_origin_custom_header_blocklist_names
}

violation contains make_diag_full("pf-cloudfront-origin-custom-header-blocklist", "ERROR", name, o.path,
	sprintf("CloudFront cannot add the reserved header %v to origin requests", [n]),
	_pf_cf_origin_custom_header_blocklist_fix, _pf_cf_origin_custom_header_blocklist_url) if {
	some name in resources_of_type("AWS::CloudFront::Distribution")
	some o in _pf_cflib_origins(name)
	some h in object.get(o.value, "OriginCustomHeaders", [])
	n := object.get(h, "HeaderName", null)
	is_string(n)
	some p in ["x-amz-", "x-edge-"]
	startswith(lower(n), p)
}
