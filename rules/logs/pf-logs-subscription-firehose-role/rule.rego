package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-logs-subscription-firehose-role", "ERROR", name,
	"Properties.RoleArn",
	"The subscription filter targets a Firehose delivery stream but sets no RoleArn; PutSubscriptionFilter fails with \"destinationArn for vendor firehose cannot be used without roleArn\"",
	"Add a RoleArn for a role logs.amazonaws.com can assume with firehose:PutRecord on the stream",
	"https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/SubscriptionFilters.html") if {
	some name in resources_of_type("AWS::Logs::SubscriptionFilter")
	_pf_lglib_dest_vendor(name) == "firehose"
	_pf_lglib_absent(name, "RoleArn")
}
