package cdk_preflight

import rego.v1

_pf_cf_http_version_enum_fix := "Use http1.1, http2, http2and3 or http3"

_pf_cf_http_version_enum_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cloudfront-distribution-distributionconfig.html"

violation contains make_diag_full("pf-cloudfront-http-version-enum", "ERROR", name, "Properties.DistributionConfig",
	sprintf("HttpVersion %v is not a valid value", [hv]),
	_pf_cf_http_version_enum_fix, _pf_cf_http_version_enum_url) if {
	some name in resources_of_type("AWS::CloudFront::Distribution")
	cfg := _pf_cflib_config(name)
	hv := object.get(cfg, "HttpVersion", null)
	is_string(hv)
	not hv in {"http1.1", "http2", "http2and3", "http3"}
}
