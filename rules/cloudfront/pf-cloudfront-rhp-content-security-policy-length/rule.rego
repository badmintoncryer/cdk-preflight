package cdk_preflight

import rego.v1

_pf_cf_rhp_content_security_policy_length_fix := "Shorten the Content-Security-Policy value to 1783 characters or fewer"

_pf_cf_rhp_content_security_policy_length_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudfront-responseheaderspolicy.html"

violation contains make_diag_full("pf-cloudfront-rhp-content-security-policy-length", "ERROR", name, "Properties.ResponseHeadersPolicyConfig.SecurityHeadersConfig.ContentSecurityPolicy",
	sprintf("ContentSecurityPolicy is %v characters, over the 1783 limit", [count(v)]),
	_pf_cf_rhp_content_security_policy_length_fix, _pf_cf_rhp_content_security_policy_length_url) if {
	some name in resources_of_type("AWS::CloudFront::ResponseHeadersPolicy")
	cfgv := _pf_cflib_props(name, "ResponseHeadersPolicyConfig")
	sh := object.get(cfgv, "SecurityHeadersConfig", null)
	is_object(sh)
	csp := object.get(sh, "ContentSecurityPolicy", null)
	is_object(csp)
	v := object.get(csp, "ContentSecurityPolicy", null)
	is_string(v)
	count(v) > 1783
}
