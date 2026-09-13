package cdk_preflight

import rego.v1

_pf_cf_vpc_origin_port_range_fix := "Use 80, 443, or a port in 1024-65535"

_pf_cf_vpc_origin_port_range_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudfront-vpcorigin.html"

# 許される値はカスタムオリジンと同じで 80 / 443 / 1024-65535。1-1023 も拒否される
# （2026-09-13 us-east-1 CreateVpcOrigin: 0 / 1 / 79 / 1023 / 65536 はいずれも
# "The parameter origin port is not within allowed range."、80 / 443 / 1024 / 65535 は
# ポートの検査を抜けて Arn の検査まで進む）。
violation contains make_diag_full("pf-cloudfront-vpc-origin-port-range", "ERROR", name, "Properties.VpcOriginEndpointConfig",
	sprintf("%v %v is below the allowed range (80, 443 or 1024-65535)", [k, p]),
	_pf_cf_vpc_origin_port_range_fix, _pf_cf_vpc_origin_port_range_url) if {
	some name in resources_of_type("AWS::CloudFront::VpcOrigin")
	cfgv := _pf_cflib_props(name, "VpcOriginEndpointConfig")
	some k in ["HTTPPort", "HTTPSPort"]
	raw := object.get(cfgv, k, "__pf_absent")
	raw != "__pf_absent"
	p := to_number(raw)
	p != 80
	p != 443
	p < 1024
}

violation contains make_diag_full("pf-cloudfront-vpc-origin-port-range", "ERROR", name, "Properties.VpcOriginEndpointConfig",
	sprintf("%v %v is above the allowed range (80, 443 or 1024-65535)", [k, p]),
	_pf_cf_vpc_origin_port_range_fix, _pf_cf_vpc_origin_port_range_url) if {
	some name in resources_of_type("AWS::CloudFront::VpcOrigin")
	cfgv := _pf_cflib_props(name, "VpcOriginEndpointConfig")
	some k in ["HTTPPort", "HTTPSPort"]
	raw := object.get(cfgv, k, "__pf_absent")
	raw != "__pf_absent"
	p := to_number(raw)
	p > 65535
}
