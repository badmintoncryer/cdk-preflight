package cdk_preflight

import rego.v1

_pf_cf_origin_request_policy_header_behavior_items_fix := "List at least one entry in Headers"

_pf_cf_origin_request_policy_header_behavior_items_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudfront-originrequestpolicy.html"

violation contains make_diag_full("pf-cloudfront-origin-request-policy-header-behavior-items", "ERROR", name, "Properties.OriginRequestPolicyConfig.HeadersConfig",
	sprintf("HeaderBehavior %v requires at least one entry in Headers", [bh]),
	_pf_cf_origin_request_policy_header_behavior_items_fix, _pf_cf_origin_request_policy_header_behavior_items_url) if {
	some name in resources_of_type("AWS::CloudFront::OriginRequestPolicy")
	cfgv := _pf_cflib_props(name, "OriginRequestPolicyConfig")
	sc := object.get(cfgv, "HeadersConfig", null)
	is_object(sc)
	bh := object.get(sc, "HeaderBehavior", null)
	bh in {"whitelist", "allExcept", "allViewerAndWhitelistCloudFront"}
	count(object.get(sc, "Headers", [])) == 0
}
