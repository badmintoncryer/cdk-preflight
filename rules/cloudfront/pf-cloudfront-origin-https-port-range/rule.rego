package cdk_preflight

import rego.v1

_pf_cf_origin_https_port_range_fix := "Use 80, 443, or a port in 1024-65535 for HTTPSPort"

_pf_cf_origin_https_port_range_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cloudfront-distribution-origin.html"

violation contains make_diag_full("pf-cloudfront-origin-https-port-range", "ERROR", name, o.path,
	sprintf("HTTPSPort %v is below the allowed range (80, 443 or 1024-65535)", [p]),
	_pf_cf_origin_https_port_range_fix, _pf_cf_origin_https_port_range_url) if {
	some name in resources_of_type("AWS::CloudFront::Distribution")
	some o in _pf_cflib_origins(name)
	oc := object.get(o.value, "CustomOriginConfig", null)
	is_object(oc)
	praw := object.get(oc, "HTTPSPort", "__pf_absent")
	praw != "__pf_absent"
	p := to_number(praw)
	p != 80
	p != 443
	p < 1024
}

violation contains make_diag_full("pf-cloudfront-origin-https-port-range", "ERROR", name, o.path,
	sprintf("HTTPSPort %v is above the allowed range (80, 443 or 1024-65535)", [p]),
	_pf_cf_origin_https_port_range_fix, _pf_cf_origin_https_port_range_url) if {
	some name in resources_of_type("AWS::CloudFront::Distribution")
	some o in _pf_cflib_origins(name)
	oc := object.get(o.value, "CustomOriginConfig", null)
	is_object(oc)
	praw := object.get(oc, "HTTPSPort", "__pf_absent")
	praw != "__pf_absent"
	p := to_number(praw)
	p > 65535
}
