package cdk_preflight

import rego.v1

_pf_s3xzmm_fix := "Use the same availability zone id in the bucket name suffix and in LocationName"

_pf_s3xzmm_url := "https://docs.aws.amazon.com/AmazonS3/latest/userguide/directory-bucket-naming-rules.html"

violation contains make_diag_full("pf-s3express-bucket-zone-mismatch", "ERROR", name, "Properties.LocationName",
	sprintf("the bucket name encodes zone '%v' but LocationName is '%v'; the two must name the same availability zone", [z, loc]),
	_pf_s3xzmm_fix, _pf_s3xzmm_url) if {
	some name in resources_of_type("AWS::S3Express::DirectoryBucket")
	bn := _pf_s3xlib_lit(name, "Properties.BucketName")
	z := _pf_s3xlib_zone(bn)
	loc := _pf_s3xlib_lit(name, "Properties.LocationName")
	loc != z
}
