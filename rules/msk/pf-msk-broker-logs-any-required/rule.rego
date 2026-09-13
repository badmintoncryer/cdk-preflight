package cdk_preflight

import rego.v1

# Every member of BrokerLogs is optional in the schema, so an empty object passes every earlier
# layer and the create fails with "You must define one or more of the following broker log types:
# CloudWatch Logs, Kinesis Data Firehose, Amazon S3. ... InvalidParameter: brokerLogs".
violation contains make_diag_full("pf-msk-broker-logs-any-required", "ERROR", name,
	"Properties.LoggingInfo.BrokerLogs",
	"BrokerLogs names no destination; the create fails with \"You must define one or more of the following broker log types: CloudWatch Logs, Kinesis Data Firehose, Amazon S3\"",
	"Declare S3, Firehose or CloudWatchLogs under BrokerLogs, or drop LoggingInfo altogether",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-cluster-brokerlogs.html") if {
	some name in resources_of_type("AWS::MSK::Cluster")
	props := input.resources[name].properties
	is_object(props)
	logs := object.get(props, ["LoggingInfo", "BrokerLogs"], null)
	is_object(logs)
	named := [k | some k in object.keys(logs); k in {"S3", "Firehose", "CloudWatchLogs"}]
	count(named) == 0
}
