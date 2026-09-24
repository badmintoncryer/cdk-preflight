package cdk_preflight

import rego.v1

# 4 つの宛先プロパティはどれも Required: No なので、スキーマは「宛先ゼロ」を通す。
violation contains make_diag_full("pf-ses-event-destination-requires-destination", "ERROR", name,
	"Properties.EventDestination",
	"EventDestination has none of CloudWatchDestination, EventBridgeDestination, KinesisFirehoseDestination and SnsDestination; the create fails with \"Resource of type 'AWS::SES::ConfigurationSetEventDestination' with identifier 'event destination must present' was not found.\"",
	"Add exactly one destination block to EventDestination",
	"https://docs.aws.amazon.com/ses/latest/APIReference-V2/API_EventDestinationDefinition.html") if {
	some name in resources_of_type("AWS::SES::ConfigurationSetEventDestination")
	_pf_ses_ed(name)
	not _pf_ses_ed_any(name)
}
