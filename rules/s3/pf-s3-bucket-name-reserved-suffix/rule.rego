package cdk_preflight

import rego.v1

_pf_s3nsx_fix := "Drop the -s3alias, --ol-s3, .mrap, --x-s3 or --table-s3 suffix from the bucket name"

_pf_s3nsx_url := "https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucketnamingrules.html"

violation contains make_diag_full("pf-s3-bucket-name-reserved-suffix", "ERROR", name, "Properties.BucketName",
	sprintf("bucket name '%v' ends with the reserved suffix '%v'", [b, s]),
	_pf_s3nsx_fix, _pf_s3nsx_url) if {
	some name in resources_of_type("AWS::S3::Bucket")
	b := _pf_s3lib_lit(resolve(name, "Properties.BucketName"))
	some s in {"-s3alias", "--ol-s3", ".mrap", "--x-s3", "--table-s3"}
	endswith(b, s)
}
