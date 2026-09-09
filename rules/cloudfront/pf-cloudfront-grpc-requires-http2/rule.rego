package cdk_preflight

import rego.v1

_pf_cf_grpc_requires_http2_fix := "Set HttpVersion to http2 or http2and3"

_pf_cf_grpc_requires_http2_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cloudfront-distribution-distributionconfig.html"

violation contains make_diag_full("pf-cloudfront-grpc-requires-http2", "ERROR", name, b.path,
	sprintf("GrpcConfig is enabled but HttpVersion is %v", [hv]),
	_pf_cf_grpc_requires_http2_fix, _pf_cf_grpc_requires_http2_url) if {
	some name in resources_of_type("AWS::CloudFront::Distribution")
	some b in _pf_cflib_behaviors(name)
	grpc := object.get(b.value, "GrpcConfig", null)
	is_object(grpc)
	object.get(grpc, "Enabled", false) == true
	hv := object.get(_pf_cflib_config(name), "HttpVersion", null)
	is_string(hv)
	not hv in {"http2", "http2and3"}
}
