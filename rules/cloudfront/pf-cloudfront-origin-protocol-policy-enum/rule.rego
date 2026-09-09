package cdk_preflight

import rego.v1

_pf_cf_origin_protocol_policy_enum_fix := "Use http-only, https-only or match-viewer"

_pf_cf_origin_protocol_policy_enum_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cloudfront-distribution-origin.html"

violation contains make_diag_full("pf-cloudfront-origin-protocol-policy-enum", "ERROR", name, o.path,
	sprintf("OriginProtocolPolicy %v is not a valid value", [pp]),
	_pf_cf_origin_protocol_policy_enum_fix, _pf_cf_origin_protocol_policy_enum_url) if {
	some name in resources_of_type("AWS::CloudFront::Distribution")
	some o in _pf_cflib_origins(name)
	oc := object.get(o.value, "CustomOriginConfig", null)
	is_object(oc)
	pp := object.get(oc, "OriginProtocolPolicy", null)
	is_string(pp)
	not pp in {"http-only", "https-only", "match-viewer"}
}
