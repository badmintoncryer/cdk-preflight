package cdk_preflight

import rego.v1

_pf_cf_oac_excludes_origin_access_identity_fix := "Use origin access control alone and leave OriginAccessIdentity empty"

_pf_cf_oac_excludes_origin_access_identity_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cloudfront-distribution-origin.html"

violation contains make_diag_full("pf-cloudfront-oac-excludes-origin-access-identity", "ERROR", name, o.path,
	sprintf("origin %v sets both OriginAccessControlId and OriginAccessIdentity (%v)", [object.get(o.value, "Id", "<unnamed>"), oai]),
	_pf_cf_oac_excludes_origin_access_identity_fix, _pf_cf_oac_excludes_origin_access_identity_url) if {
	some name in resources_of_type("AWS::CloudFront::Distribution")
	some o in _pf_cflib_origins(name)
	is_object(o.value)
	oac := object.get(o.value, "OriginAccessControlId", "__pf_absent")
	oac != "__pf_absent"
	oac != ""
	s3 := object.get(o.value, "S3OriginConfig", null)
	is_object(s3)
	oai := object.get(s3, "OriginAccessIdentity", "")
	oai != ""
}
