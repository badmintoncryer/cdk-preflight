package cdk_preflight

import rego.v1

_pf_s3xsfx_fix := "Name the directory bucket <base>--<availability-zone-id>--x-s3, e.g. mybucket--use1-az4--x-s3"

_pf_s3xsfx_url := "https://docs.aws.amazon.com/AmazonS3/latest/userguide/directory-bucket-naming-rules.html"

violation contains make_diag_full("pf-s3express-bucket-name-suffix", "ERROR", name, "Properties.BucketName",
	sprintf("directory bucket name '%v' does not end with --<availability-zone-id>--x-s3; CreateBucket rejects it", [bn]),
	_pf_s3xsfx_fix, _pf_s3xsfx_url) if {
	some name in resources_of_type("AWS::S3Express::DirectoryBucket")
	bn := _pf_s3xlib_lit(name, "Properties.BucketName")
	not regex.match("--[a-z0-9-]+--x-s3$", bn)
}
