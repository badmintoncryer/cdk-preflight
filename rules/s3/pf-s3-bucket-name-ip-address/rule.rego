package cdk_preflight

import rego.v1

_pf_s3nip_fix := "Use a name that is not formatted as four dot-separated numbers"

_pf_s3nip_url := "https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucketnamingrules.html"

violation contains make_diag_full("pf-s3-bucket-name-ip-address", "ERROR", name, "Properties.BucketName",
	sprintf("bucket name '%v' is formatted as an IP address; S3 rejects such names", [b]),
	_pf_s3nip_fix, _pf_s3nip_url) if {
	some name in resources_of_type("AWS::S3::Bucket")
	b := _pf_s3lib_lit(resolve(name, "Properties.BucketName"))
	regex.match("^[0-9]+[.][0-9]+[.][0-9]+[.][0-9]+$", b)
}
