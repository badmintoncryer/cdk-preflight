package cdk_preflight

import rego.v1

_pf_cf_response_headers_policy_name_charset_fix := "Use only A-Z, a-z, 0-9, - and _ in the policy name"

_pf_cf_response_headers_policy_name_charset_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudfront-responseheaderspolicy.html"

violation contains make_diag_full("pf-cloudfront-response-headers-policy-name-charset", "ERROR", name, "Properties.ResponseHeadersPolicyConfig.Name",
	sprintf("ResponseHeadersPolicyConfig.Name '%s' is rejected by the service: alphanumerics, dash and underscore", [v]),
	_pf_cf_response_headers_policy_name_charset_fix, _pf_cf_response_headers_policy_name_charset_url) if {
	some name in resources_of_type("AWS::CloudFront::ResponseHeadersPolicy")
	cfgv := _pf_cflib_props(name, "ResponseHeadersPolicyConfig")
	v := object.get(cfgv, "Name", null)
	is_string(v)
	not regex.match(`^[a-zA-Z0-9_-]+$`, v)
}
