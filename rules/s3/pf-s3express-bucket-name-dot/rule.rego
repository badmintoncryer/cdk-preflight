package cdk_preflight

import rego.v1

_pf_s3xdot_fix := "Remove the periods from the directory bucket name"

_pf_s3xdot_url := "https://docs.aws.amazon.com/AmazonS3/latest/userguide/directory-bucket-naming-rules.html"

violation contains make_diag_full("pf-s3express-bucket-name-dot", "ERROR", name, "Properties.BucketName",
	sprintf("directory bucket name '%v' contains a period; directory bucket names accept only lowercase letters, digits and hyphens", [bn]),
	_pf_s3xdot_fix, _pf_s3xdot_url) if {
	some name in resources_of_type("AWS::S3Express::DirectoryBucket")
	bn := _pf_s3xlib_lit(name, "Properties.BucketName")
	contains(bn, ".")
}
