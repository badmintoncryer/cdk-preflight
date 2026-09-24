package cdk_preflight

import rego.v1

# 空配列はスキーマを通る（minItems が無い）が、サービスは受け取らない。
violation contains make_diag_full("pf-ses-event-destination-matching-event-types-nonempty", "ERROR", name,
	"Properties.EventDestination.MatchingEventTypes",
	"MatchingEventTypes is empty; the event destination create fails with \"At least one event type must be specified.\"",
	"List at least one event type (e.g. SEND)",
	"https://docs.aws.amazon.com/ses/latest/APIReference-V2/API_EventDestinationDefinition.html") if {
	some name in resources_of_type("AWS::SES::ConfigurationSetEventDestination")
	types := object.get(_pf_ses_ed(name), "MatchingEventTypes", null)
	is_array(types)
	count(types) == 0
}
