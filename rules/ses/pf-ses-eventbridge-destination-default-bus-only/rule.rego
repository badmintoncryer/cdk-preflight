package cdk_preflight

import rego.v1

# SES が publish できるのは default バスだけ。スキーマの pattern は
# `event-bus/[^:]+` で任意のバス名を通す。
violation contains make_diag_full("pf-ses-eventbridge-destination-default-bus-only", "ERROR", name,
	"Properties.EventDestination.EventBridgeDestination.EventBusArn",
	sprintf("EventBusArn '%v' is not the default event bus; the event destination create fails with \"Invalid Event Bridge destination, must be default bus.\"", [arn]),
	"Point EventBusArn at the account's default bus (arn:<partition>:events:<region>:<account>:event-bus/default) and route from there",
	"https://docs.aws.amazon.com/ses/latest/APIReference-V2/API_EventBridgeDestination.html") if {
	some name in resources_of_type("AWS::SES::ConfigurationSetEventDestination")
	arn := resolve(name, "Properties.EventDestination.EventBridgeDestination.EventBusArn")
	_pf_ses_lit(arn)
	not endswith(arn, ":event-bus/default")
}
