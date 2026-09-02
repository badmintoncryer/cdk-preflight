package cdk_preflight

import rego.v1

# Transfer Acceleration endpoints are DNS-based, so bucket names containing
# periods are rejected at creation. Only a literal BucketName is checkable;
# CDK-generated names never contain periods anyway.
violation contains make_diag_full("pf-s3-accelerate-dotted-name", "ERROR", name,
	"Properties.AccelerateConfiguration.AccelerationStatus",
	sprintf("Bucket name '%s' contains periods, which Transfer Acceleration does not support; CreateBucket fails with \"S3 Transfer Acceleration is not supported for buckets with periods (.) in their names\"", [bn]),
	"Rename the bucket without periods, or drop AccelerateConfiguration",
	"https://docs.aws.amazon.com/AmazonS3/latest/userguide/transfer-acceleration.html") if {
	some name in resources_of_type("AWS::S3::Bucket")
	resolve(name, "Properties.AccelerateConfiguration.AccelerationStatus") == "Enabled"
	bn := resolve(name, "Properties.BucketName")
	is_string(bn)
	contains(bn, ".")
}
