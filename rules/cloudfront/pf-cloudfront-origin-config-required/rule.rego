package cdk_preflight

import rego.v1

_pf_cf_origin_config_required_fix := "Add S3OriginConfig, CustomOriginConfig or VpcOriginConfig to the origin"

_pf_cf_origin_config_required_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cloudfront-distribution-distributionconfig.html"

violation contains make_diag_full("pf-cloudfront-origin-config-required", "ERROR", name, o.path,
	sprintf("origin %v has none of S3OriginConfig / CustomOriginConfig / VpcOriginConfig", [object.get(o.value, "Id", "<unnamed>")]),
	_pf_cf_origin_config_required_fix, _pf_cf_origin_config_required_url) if {
	some name in resources_of_type("AWS::CloudFront::Distribution")
	some o in _pf_cflib_origins(name)
	is_object(o.value)
	object.get(o.value, "S3OriginConfig", "__pf_absent") == "__pf_absent"
	object.get(o.value, "CustomOriginConfig", "__pf_absent") == "__pf_absent"
	object.get(o.value, "VpcOriginConfig", "__pf_absent") == "__pf_absent"
}
