package cdk_preflight

import rego.v1

_pf_cf_origin_request_policy_excludes_forwarded_values_fix := "Drop ForwardedValues and keep the origin request policy"

_pf_cf_origin_request_policy_excludes_forwarded_values_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cloudfront-distribution-cachebehavior.html"

violation contains make_diag_full("pf-cloudfront-origin-request-policy-excludes-forwarded-values", "ERROR", name, b.path,
	"a cache behavior cannot set both OriginRequestPolicyId and the legacy ForwardedValues",
	_pf_cf_origin_request_policy_excludes_forwarded_values_fix, _pf_cf_origin_request_policy_excludes_forwarded_values_url) if {
	some name in resources_of_type("AWS::CloudFront::Distribution")
	some b in _pf_cflib_behaviors(name)
	is_object(b.value)
	object.get(b.value, "OriginRequestPolicyId", "__pf_absent") != "__pf_absent"
	object.get(b.value, "ForwardedValues", "__pf_absent") != "__pf_absent"
}
