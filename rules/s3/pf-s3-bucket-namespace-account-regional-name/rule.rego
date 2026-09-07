package cdk_preflight

import rego.v1

_pf_s3bns_fix := "Replace BucketName with BucketNamePrefix for a BucketNamespace of account-regional"

_pf_s3bns_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-s3-bucket.html"

violation contains make_diag_full("pf-s3-bucket-namespace-account-regional-name", "ERROR", name, "Properties.BucketName",
	"BucketNamespace is account-regional, where S3 derives the name; use BucketNamePrefix instead of BucketName",
	_pf_s3bns_fix, _pf_s3bns_url) if {
	some name in resources_of_type("AWS::S3::Bucket")
	resolve(name, "Properties.BucketNamespace") == "account-regional"
	props := input.resources[name].properties
	is_object(props)
	object.get(props, "BucketName", "__pf_absent") != "__pf_absent"
}
