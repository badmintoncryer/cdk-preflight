package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-synthetics-canary-code-s3-key-required", "ERROR", name,
	"Properties.Code.S3Key",
	"Code.S3Bucket names a bucket but Code.S3Key is missing; the bucket alone does not locate the script and CreateCanary answers \"Missing S3 Key\"",
	"Add Code.S3Key with the object key of the canary's zip, or pass the script inline through Code.Script",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-synthetics-canary-code.html") if {
	some name in resources_of_type("AWS::Synthetics::Canary")
	_pf_synlib_present(name, ["Code", "S3Bucket"])
	_pf_synlib_absent(name, ["Code", "S3Key"])
}
