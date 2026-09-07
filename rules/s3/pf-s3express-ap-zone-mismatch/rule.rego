package cdk_preflight

import rego.v1

_pf_s3xapz_fix := "Use the bucket zone id in the access point name suffix"

_pf_s3xapz_url := "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-points-directory-buckets-restrictions-limitations-naming-rules.html"

violation contains make_diag_full("pf-s3express-ap-zone-mismatch", "ERROR", name, "Properties.Name",
	sprintf("the access point name encodes zone '%v' but its bucket lives in '%v'; an access point must sit in the bucket zone", [z, bz]),
	_pf_s3xapz_fix, _pf_s3xapz_url) if {
	some name in resources_of_type("AWS::S3Express::AccessPoint")
	n := _pf_s3xlib_lit(name, "Properties.Name")
	z := _pf_s3xlib_zone(n)
	bz := _pf_s3xlib_zone(_pf_s3xlib_bucketname(name, "Properties.Bucket"))
	z != bz
}
