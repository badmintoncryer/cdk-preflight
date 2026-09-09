package cdk_preflight

import rego.v1

_pf_cf_vpc_origin_port_range_fix := "Use a port in 1-65535"

_pf_cf_vpc_origin_port_range_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudfront-vpcorigin.html"

violation contains make_diag_full("pf-cloudfront-vpc-origin-port-range", "ERROR", name, "Properties.VpcOriginEndpointConfig",
	sprintf("%v %v is below 1", [k, p]),
	_pf_cf_vpc_origin_port_range_fix, _pf_cf_vpc_origin_port_range_url) if {
	some name in resources_of_type("AWS::CloudFront::VpcOrigin")
	cfgv := _pf_cflib_props(name, "VpcOriginEndpointConfig")
	some k in ["HTTPPort", "HTTPSPort"]
	raw := object.get(cfgv, k, "__pf_absent")
	raw != "__pf_absent"
	p := to_number(raw)
	p < 1
}

violation contains make_diag_full("pf-cloudfront-vpc-origin-port-range", "ERROR", name, "Properties.VpcOriginEndpointConfig",
	sprintf("%v %v is above 65535", [k, p]),
	_pf_cf_vpc_origin_port_range_fix, _pf_cf_vpc_origin_port_range_url) if {
	some name in resources_of_type("AWS::CloudFront::VpcOrigin")
	cfgv := _pf_cflib_props(name, "VpcOriginEndpointConfig")
	some k in ["HTTPPort", "HTTPSPort"]
	raw := object.get(cfgv, k, "__pf_absent")
	raw != "__pf_absent"
	p := to_number(raw)
	p > 65535
}
