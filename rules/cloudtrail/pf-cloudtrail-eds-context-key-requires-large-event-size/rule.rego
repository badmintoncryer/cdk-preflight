package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cloudtrail-eds-context-key-requires-large-event-size", "ERROR", name,
	"Properties.MaxEventSize",
	"the event data store sets ContextKeySelectors without MaxEventSize Large; enriched context keys only fit the large event size",
	"Set MaxEventSize to Large, or drop ContextKeySelectors",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cloudtrail-eventdatastore.html") if {
	some name in resources_of_type("AWS::CloudTrail::EventDataStore")
	count(_pf_ctlib_context_key_selectors(name)) > 0
	object.get(_pf_ctlib_props(name), "MaxEventSize", null) != "Large"
}
