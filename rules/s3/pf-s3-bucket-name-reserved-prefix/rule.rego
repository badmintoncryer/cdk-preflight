package cdk_preflight

import rego.v1

_pf_s3npx_fix := "Drop the xn--, sthree- or amzn-s3-demo- prefix from the bucket name"

_pf_s3npx_url := "https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucketnamingrules.html"

violation contains make_diag_full("pf-s3-bucket-name-reserved-prefix", "ERROR", name, "Properties.BucketName",
	sprintf("bucket name '%v' starts with the reserved prefix '%v'", [b, p]),
	_pf_s3npx_fix, _pf_s3npx_url) if {
	some name in resources_of_type("AWS::S3::Bucket")
	b := _pf_s3lib_lit(resolve(name, "Properties.BucketName"))
	some p in {"xn--", "sthree-", "amzn-s3-demo-"}
	startswith(b, p)
}
