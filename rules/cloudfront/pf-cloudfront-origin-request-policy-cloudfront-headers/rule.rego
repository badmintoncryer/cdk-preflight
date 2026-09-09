package cdk_preflight

import rego.v1

_pf_cf_origin_request_policy_cloudfront_headers_fix := "List only CloudFront-* headers, or use a different HeaderBehavior"

_pf_cf_origin_request_policy_cloudfront_headers_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudfront-originrequestpolicy.html"

violation contains make_diag_full("pf-cloudfront-origin-request-policy-cloudfront-headers", "ERROR", name, "Properties.OriginRequestPolicyConfig.HeadersConfig",
	sprintf("%v is not a CloudFront-* header", [h]),
	_pf_cf_origin_request_policy_cloudfront_headers_fix, _pf_cf_origin_request_policy_cloudfront_headers_url) if {
	some name in resources_of_type("AWS::CloudFront::OriginRequestPolicy")
	cfgv := _pf_cflib_props(name, "OriginRequestPolicyConfig")
	hc := object.get(cfgv, "HeadersConfig", null)
	is_object(hc)
	object.get(hc, "HeaderBehavior", null) == "allViewerAndWhitelistCloudFront"
	some h in object.get(hc, "Headers", [])
	is_string(h)
	not startswith(lower(h), "cloudfront-")
}
