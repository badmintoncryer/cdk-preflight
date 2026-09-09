package cdk_preflight

import rego.v1

_pf_cf_grpc_requires_post_method_fix := "Allow all seven methods on the behavior that enables gRPC"

_pf_cf_grpc_requires_post_method_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cloudfront-distribution-cachebehavior.html"

violation contains make_diag_full("pf-cloudfront-grpc-requires-post-method", "ERROR", name, b.path,
	sprintf("GrpcConfig is enabled but AllowedMethods %v does not include POST", [am]),
	_pf_cf_grpc_requires_post_method_fix, _pf_cf_grpc_requires_post_method_url) if {
	some name in resources_of_type("AWS::CloudFront::Distribution")
	some b in _pf_cflib_behaviors(name)
	grpc := object.get(b.value, "GrpcConfig", null)
	is_object(grpc)
	object.get(grpc, "Enabled", false) == true
	am := object.get(b.value, "AllowedMethods", ["GET", "HEAD"])
	is_array(am)
	not "POST" in am
}
