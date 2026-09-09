package cdk_preflight

import rego.v1

_pf_cf_logging_bucket_format_fix := "Use <bucket>.s3.<region>.amazonaws.com"

_pf_cf_logging_bucket_format_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cloudfront-distribution-distributionconfig.html"

violation contains make_diag_full("pf-cloudfront-logging-bucket-format", "ERROR", name, "Properties.DistributionConfig",
	sprintf("Logging.Bucket %v is not an S3 bucket DNS name", [bk]),
	_pf_cf_logging_bucket_format_fix, _pf_cf_logging_bucket_format_url) if {
	some name in resources_of_type("AWS::CloudFront::Distribution")
	cfg := _pf_cflib_config(name)
	lg := object.get(cfg, "Logging", null)
	is_object(lg)
	bk := object.get(lg, "Bucket", null)
	is_string(bk)
	bk != ""
	not endswith(bk, ".amazonaws.com")
}
