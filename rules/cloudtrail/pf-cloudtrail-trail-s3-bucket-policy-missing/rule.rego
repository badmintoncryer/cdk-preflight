package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cloudtrail-trail-s3-bucket-policy-missing", "ERROR", name,
	"Properties.S3BucketName",
	sprintf("bucket '%v' has no bucket policy granting s3:PutObject to cloudtrail.amazonaws.com; CreateTrail fails with \"Incorrect S3 bucket policy is detected for bucket\"", [b]),
	"Attach an AWS::S3::BucketPolicy allowing cloudtrail.amazonaws.com to call s3:GetBucketAcl and s3:PutObject on the bucket",
	"https://docs.aws.amazon.com/awscloudtrail/latest/userguide/create_trail_bucket_policy.html") if {
	some name in resources_of_type("AWS::CloudTrail::Trail")
	b := resolve(name, "Properties.S3BucketName")
	b in resources_of_type("AWS::S3::Bucket")
	count(_pf_ctlib_ct_write_policies(b)) == 0
}
