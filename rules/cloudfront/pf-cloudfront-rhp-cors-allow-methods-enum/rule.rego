package cdk_preflight

import rego.v1

_pf_cf_rhp_cors_allow_methods_enum_fix := "Use GET, POST, OPTIONS, PUT, DELETE, PATCH, HEAD or ALL"

_pf_cf_rhp_cors_allow_methods_enum_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudfront-responseheaderspolicy.html"

violation contains make_diag_full("pf-cloudfront-rhp-cors-allow-methods-enum", "ERROR", name, "Properties.ResponseHeadersPolicyConfig.CorsConfig.AccessControlAllowMethods",
	sprintf("%v is not a valid AccessControlAllowMethods value", [m]),
	_pf_cf_rhp_cors_allow_methods_enum_fix, _pf_cf_rhp_cors_allow_methods_enum_url) if {
	some name in resources_of_type("AWS::CloudFront::ResponseHeadersPolicy")
	cfgv := _pf_cflib_props(name, "ResponseHeadersPolicyConfig")
	cc := object.get(cfgv, "CorsConfig", null)
	is_object(cc)
	sub := object.get(cc, "AccessControlAllowMethods", null)
	is_object(sub)
	its := object.get(sub, "Items", [])
	is_array(its)
	some m in its
	is_string(m)
	not m in {"ALL", "DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"}
}
