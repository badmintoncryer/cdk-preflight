package cdk_preflight

import rego.v1

_pf_cf_origin_path_format_fix := "Write the origin path as /path with no trailing slash"

_pf_cf_origin_path_format_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cloudfront-distribution-origin.html"

violation contains make_diag_full("pf-cloudfront-origin-path-format", "ERROR", name, o.path,
	sprintf("OriginPath %v does not start with /", [op]),
	_pf_cf_origin_path_format_fix, _pf_cf_origin_path_format_url) if {
	some name in resources_of_type("AWS::CloudFront::Distribution")
	some o in _pf_cflib_origins(name)
	is_object(o.value)
	op := object.get(o.value, "OriginPath", "")
	is_string(op)
	op != ""
	not startswith(op, "/")
}

violation contains make_diag_full("pf-cloudfront-origin-path-format", "ERROR", name, o.path,
	sprintf("OriginPath %v must not end with /", [op]),
	_pf_cf_origin_path_format_fix, _pf_cf_origin_path_format_url) if {
	some name in resources_of_type("AWS::CloudFront::Distribution")
	some o in _pf_cflib_origins(name)
	is_object(o.value)
	op := object.get(o.value, "OriginPath", "")
	is_string(op)
	op != "/"
	endswith(op, "/")
}
