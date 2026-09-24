package cdk_preflight

import rego.v1

# スキーマは MatchingEventTypes を素の文字列配列として通す（許容値の一覧を持たない）。
violation contains make_diag_full("pf-ses-event-destination-matching-event-types-enum", "ERROR", name,
	"Properties.EventDestination.MatchingEventTypes",
	sprintf("MatchingEventTypes contains '%v'; the event destination create fails with \"The event destination contains an invalid event type.\"", [t]),
	"Use SEND, REJECT, BOUNCE, COMPLAINT, DELIVERY, OPEN, CLICK, RENDERING_FAILURE, DELIVERY_DELAY or SUBSCRIPTION",
	"https://docs.aws.amazon.com/ses/latest/APIReference-V2/API_EventDestinationDefinition.html") if {
	some name in resources_of_type("AWS::SES::ConfigurationSetEventDestination")
	some item in flatten_list(name, "Properties.EventDestination.MatchingEventTypes")
	t := item.value
	_pf_ses_lit(t)
	not t in _pf_ses_event_types
}
