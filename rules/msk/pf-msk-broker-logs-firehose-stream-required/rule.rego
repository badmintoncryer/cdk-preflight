package cdk_preflight

import rego.v1

# DeliveryStream is Required: No in the schema because the destination is only needed when the log type is
# enabled - the create then fails with "To use Kinesis Data Firehose as a destination for broker logs, you must specify a delivery stream.
# ... InvalidParameter: brokerLogs".
violation contains make_diag_full("pf-msk-broker-logs-firehose-stream-required", "ERROR", name,
	"Properties.LoggingInfo.BrokerLogs.Firehose.DeliveryStream",
	"Kinesis Data Firehose broker logs are enabled without a DeliveryStream; the create fails with \"To use Kinesis Data Firehose as a destination for broker logs, you must specify a delivery stream\"",
	"Name the DeliveryStream, or set Enabled to false",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-cluster-brokerlogs.html") if {
	some name in resources_of_type("AWS::MSK::Cluster")
	props := input.resources[name].properties
	is_object(props)
	dest := object.get(props, ["LoggingInfo", "BrokerLogs", "Firehose"], null)
	is_object(dest)
	object.get(dest, "Enabled", false) == true
	object.get(dest, "DeliveryStream", "__pf_absent") == "__pf_absent"
}
