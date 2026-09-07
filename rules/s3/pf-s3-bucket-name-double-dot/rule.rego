package cdk_preflight

import rego.v1

_pf_s3ndd_fix := "Collapse the consecutive periods in the bucket name"

_pf_s3ndd_url := "https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucketnamingrules.html"

violation contains make_diag_full("pf-s3-bucket-name-double-dot", "ERROR", name, "Properties.BucketName",
	sprintf("bucket name '%v' contains two adjacent periods", [b]),
	_pf_s3ndd_fix, _pf_s3ndd_url) if {
	some name in resources_of_type("AWS::S3::Bucket")
	b := _pf_s3lib_lit(resolve(name, "Properties.BucketName"))
	contains(b, "..")
}
