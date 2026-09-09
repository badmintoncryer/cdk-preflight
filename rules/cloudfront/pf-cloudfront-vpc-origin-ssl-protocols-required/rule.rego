package cdk_preflight

import rego.v1

_pf_cf_vpc_origin_ssl_protocols_required_fix := "Add OriginSSLProtocols (for example [\"TLSv1.2\"])"

_pf_cf_vpc_origin_ssl_protocols_required_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudfront-vpcorigin.html"

violation contains make_diag_full("pf-cloudfront-vpc-origin-ssl-protocols-required", "ERROR", name, "Properties.VpcOriginEndpointConfig",
	sprintf("OriginProtocolPolicy is %v but OriginSSLProtocols is not set", [pp]),
	_pf_cf_vpc_origin_ssl_protocols_required_fix, _pf_cf_vpc_origin_ssl_protocols_required_url) if {
	some name in resources_of_type("AWS::CloudFront::VpcOrigin")
	cfgv := _pf_cflib_props(name, "VpcOriginEndpointConfig")
	pp := object.get(cfgv, "OriginProtocolPolicy", null)
	pp in {"https-only", "match-viewer"}
	object.get(cfgv, "OriginSSLProtocols", "__pf_absent") == "__pf_absent"
}
