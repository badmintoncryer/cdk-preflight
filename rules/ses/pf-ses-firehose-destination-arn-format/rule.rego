package cdk_preflight

import rego.v1

# SnsDestination と EventBridgeDestination の ARN はスキーマが pattern を持つのに、
# KinesisFirehoseDestination の 2 つは素の文字列。形式検査はリージョン検査より先に走る。
violation contains make_diag_full("pf-ses-firehose-destination-arn-format", "ERROR", name,
	"Properties.EventDestination.KinesisFirehoseDestination.DeliveryStreamARN",
	sprintf("DeliveryStreamARN '%v' is not a Firehose delivery stream ARN; the event destination create fails with \"Invalid delivery stream ARN %v should have the form <arn:aws:firehose:region:[account-id]:deliverystream/[stream-name]>\"", [arn, arn]),
	"Use arn:<partition>:firehose:<region>:<account>:deliverystream/<stream name>",
	"https://docs.aws.amazon.com/ses/latest/APIReference-V2/API_EventDestinationDefinition.html") if {
	some name in resources_of_type("AWS::SES::ConfigurationSetEventDestination")
	arn := resolve(name, "Properties.EventDestination.KinesisFirehoseDestination.DeliveryStreamARN")
	_pf_ses_lit(arn)
	startswith(arn, "arn:")
	not regex.match(`^arn:[^:]*:firehose:[^:]*:[^:]*:deliverystream/`, arn)
}
