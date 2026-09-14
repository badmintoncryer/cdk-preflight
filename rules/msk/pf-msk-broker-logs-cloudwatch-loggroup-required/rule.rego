package cdk_preflight

import rego.v1

# LogGroup is Required: No in the schema because the destination is only needed when the log type is
# enabled - the create then fails with "To use CloudWatch Logs as a destination for broker logs, you must specify a CloudWatch log group.
# ... InvalidParameter: brokerLogs".
violation contains make_diag_full("pf-msk-broker-logs-cloudwatch-loggroup-required", "ERROR", name,
	"Properties.LoggingInfo.BrokerLogs.CloudWatchLogs.LogGroup",
	"CloudWatch Logs broker logs are enabled without a LogGroup; the create fails with \"To use CloudWatch Logs as a destination for broker logs, you must specify a CloudWatch log group\"",
	"Name the LogGroup, or set Enabled to false",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-cluster-brokerlogs.html") if {
	some name in resources_of_type("AWS::MSK::Cluster")
	props := input.resources[name].properties
	is_object(props)
	dest := object.get(props, ["LoggingInfo", "BrokerLogs", "CloudWatchLogs"], null)
	is_object(dest)
	object.get(dest, "Enabled", false) == true
	object.get(dest, "LogGroup", "__pf_absent") == "__pf_absent"
}
