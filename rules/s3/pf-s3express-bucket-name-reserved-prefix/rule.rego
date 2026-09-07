package cdk_preflight

import rego.v1

_pf_s3xrsv_fix := "Drop the xn--, sthree- or amzn-s3-demo- prefix from the bucket name"

_pf_s3xrsv_url := "https://docs.aws.amazon.com/AmazonS3/latest/userguide/directory-bucket-naming-rules.html"

violation contains make_diag_full("pf-s3express-bucket-name-reserved-prefix", "ERROR", name, "Properties.BucketName",
	sprintf("directory bucket name '%v' starts with the reserved prefix '%v'", [bn, p]),
	_pf_s3xrsv_fix, _pf_s3xrsv_url) if {
	some name in resources_of_type("AWS::S3Express::DirectoryBucket")
	bn := _pf_s3xlib_lit(name, "Properties.BucketName")
	some p in {"xn--", "sthree-", "amzn-s3-demo-"}
	startswith(bn, p)
}
