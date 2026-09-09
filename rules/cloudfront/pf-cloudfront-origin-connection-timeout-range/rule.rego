package cdk_preflight

import rego.v1

_pf_cf_origin_connection_timeout_range_fix := "Use a value between 1 and 10 for ConnectionTimeout"

_pf_cf_origin_connection_timeout_range_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cloudfront-distribution-origin.html"

violation contains make_diag_full("pf-cloudfront-origin-connection-timeout-range", "ERROR", name, o.path,
	sprintf("ConnectionTimeout %v is less than 1", [v]),
	_pf_cf_origin_connection_timeout_range_fix, _pf_cf_origin_connection_timeout_range_url) if {
	some name in resources_of_type("AWS::CloudFront::Distribution")
	some o in _pf_cflib_origins(name)
	is_object(o.value)
	raw := object.get(o.value, "ConnectionTimeout", "__pf_absent")
	raw != "__pf_absent"
	v := to_number(raw)
	v < 1
}

violation contains make_diag_full("pf-cloudfront-origin-connection-timeout-range", "ERROR", name, o.path,
	sprintf("ConnectionTimeout %v is greater than 10", [v]),
	_pf_cf_origin_connection_timeout_range_fix, _pf_cf_origin_connection_timeout_range_url) if {
	some name in resources_of_type("AWS::CloudFront::Distribution")
	some o in _pf_cflib_origins(name)
	is_object(o.value)
	raw := object.get(o.value, "ConnectionTimeout", "__pf_absent")
	raw != "__pf_absent"
	v := to_number(raw)
	v > 10
}
