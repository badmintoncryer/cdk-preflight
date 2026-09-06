package cdk_preflight

import rego.v1

_pf_s3xbke_fix := "Remove BucketKeyEnabled or set it to true; directory buckets always use S3 Bucket Keys"

_pf_s3xbke_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3express-directorybucket-serversideencryptionrule.html"

violation contains make_diag_full("pf-s3express-bucket-key-enabled-false", "ERROR", name,
	sprintf("Properties.BucketEncryption.ServerSideEncryptionConfiguration.%d.BucketKeyEnabled", [c.index]),
	"BucketKeyEnabled is false; directory buckets always use S3 Bucket Keys and reject false",
	_pf_s3xbke_fix, _pf_s3xbke_url) if {
	some name in resources_of_type("AWS::S3Express::DirectoryBucket")
	some c in flatten_list(name, "Properties.BucketEncryption.ServerSideEncryptionConfiguration")
	is_object(c.value)
	object.get(c.value, "BucketKeyEnabled", true) == false
}
