package cdk_preflight

import rego.v1

_pf_cf_viewer_protocol_policy_enum_fix := "Use allow-all, https-only or redirect-to-https"

_pf_cf_viewer_protocol_policy_enum_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cloudfront-distribution-cachebehavior.html"

violation contains make_diag_full("pf-cloudfront-viewer-protocol-policy-enum", "ERROR", name, b.path,
	sprintf("ViewerProtocolPolicy %v is not a valid value", [vp]),
	_pf_cf_viewer_protocol_policy_enum_fix, _pf_cf_viewer_protocol_policy_enum_url) if {
	some name in resources_of_type("AWS::CloudFront::Distribution")
	some b in _pf_cflib_behaviors(name)
	vp := object.get(b.value, "ViewerProtocolPolicy", null)
	is_string(vp)
	not vp in {"allow-all", "https-only", "redirect-to-https"}
}
