package cdk_preflight

import rego.v1

_pf_lgsdv_vendors := {"lambda", "kinesis", "firehose", "logs"}

violation contains make_diag_full("pf-logs-subscription-destination-vendor", "ERROR", name,
	"Properties.DestinationArn",
	sprintf("The destination ARN names the service '%s'; PutSubscriptionFilter fails with \"PutSubscriptionFilter operation cannot work with destinationArn for vendor %s\"", [vendor, vendor]),
	"Send the subscription to a Lambda function, a Kinesis stream, a Firehose delivery stream or a cross-account CloudWatch Logs destination",
	"https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/SubscriptionFilters.html") if {
	some name in resources_of_type("AWS::Logs::SubscriptionFilter")
	vendor := _pf_lglib_dest_vendor(name)
	not vendor in _pf_lgsdv_vendors
}
