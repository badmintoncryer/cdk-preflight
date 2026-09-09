package cdk_preflight

import rego.v1

_pf_cf_origin_read_timeout_range_fix := "Use a value between 1 and 120 for OriginReadTimeout"

_pf_cf_origin_read_timeout_range_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cloudfront-distribution-origin.html"

violation contains make_diag_full("pf-cloudfront-origin-read-timeout-range", "ERROR", name, o.path,
	sprintf("OriginReadTimeout %v is less than 1", [v]),
	_pf_cf_origin_read_timeout_range_fix, _pf_cf_origin_read_timeout_range_url) if {
	some name in resources_of_type("AWS::CloudFront::Distribution")
	some o in _pf_cflib_origins(name)
	oc := object.get(o.value, "CustomOriginConfig", null)
	is_object(oc)
	vraw := object.get(oc, "OriginReadTimeout", "__pf_absent")
	vraw != "__pf_absent"
	v := to_number(vraw)
	v < 1
}

violation contains make_diag_full("pf-cloudfront-origin-read-timeout-range", "ERROR", name, o.path,
	sprintf("OriginReadTimeout %v is greater than 120", [v]),
	_pf_cf_origin_read_timeout_range_fix, _pf_cf_origin_read_timeout_range_url) if {
	some name in resources_of_type("AWS::CloudFront::Distribution")
	some o in _pf_cflib_origins(name)
	oc := object.get(o.value, "CustomOriginConfig", null)
	is_object(oc)
	vraw := object.get(oc, "OriginReadTimeout", "__pf_absent")
	vraw != "__pf_absent"
	v := to_number(vraw)
	v > 120
}
