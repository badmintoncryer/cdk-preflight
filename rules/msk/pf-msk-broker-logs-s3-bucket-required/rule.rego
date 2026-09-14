package cdk_preflight

import rego.v1

# Bucket is Required: No in the schema because the destination is only needed when the log type is
# enabled - the create then fails with "To use Amazon S3 as a destination for broker logs, you must specify an S3 bucket.
# ... InvalidParameter: brokerLogs".
violation contains make_diag_full("pf-msk-broker-logs-s3-bucket-required", "ERROR", name,
	"Properties.LoggingInfo.BrokerLogs.S3.Bucket",
	"Amazon S3 broker logs are enabled without a Bucket; the create fails with \"To use Amazon S3 as a destination for broker logs, you must specify an S3 bucket\"",
	"Name the Bucket, or set Enabled to false",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-cluster-brokerlogs.html") if {
	some name in resources_of_type("AWS::MSK::Cluster")
	props := input.resources[name].properties
	is_object(props)
	dest := object.get(props, ["LoggingInfo", "BrokerLogs", "S3"], null)
	is_object(dest)
	object.get(dest, "Enabled", false) == true
	object.get(dest, "Bucket", "__pf_absent") == "__pf_absent"
}
