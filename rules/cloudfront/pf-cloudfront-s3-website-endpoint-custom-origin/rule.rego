package cdk_preflight

import rego.v1

_pf_cf_s3_website_endpoint_custom_origin_fix := "Replace S3OriginConfig with CustomOriginConfig for a *.s3-website-* domain"

_pf_cf_s3_website_endpoint_custom_origin_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cloudfront-distribution-origin.html"

violation contains make_diag_full("pf-cloudfront-s3-website-endpoint-custom-origin", "ERROR", name, o.path,
	sprintf("origin %v is an S3 website endpoint and cannot use S3OriginConfig", [dn]),
	_pf_cf_s3_website_endpoint_custom_origin_fix, _pf_cf_s3_website_endpoint_custom_origin_url) if {
	some name in resources_of_type("AWS::CloudFront::Distribution")
	some o in _pf_cflib_origins(name)
	is_object(o.value)
	dn := object.get(o.value, "DomainName", null)
	is_string(dn)
	regex.match(`\.s3-website[.-]`, dn)
	object.get(o.value, "S3OriginConfig", "__pf_absent") != "__pf_absent"
}
