package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cloudtrail-trail-aes-network-requires-event-source", "ERROR", name,
	"Properties.AdvancedEventSelectors.FieldSelectors",
	sprintf("advanced event selector %v logs eventCategory NetworkActivity without an eventSource field; eventSource is required for network activity events", [i]),
	"Add {Field: eventSource, Equals: [<service principal>]} to the selector",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-cloudtrail-trail-advancedeventselector.html") if {
	some name in resources_of_type("AWS::CloudTrail::Trail")
	some i, s in _pf_ctlib_aes(name)
	_pf_ctlib_category_is(s, "NetworkActivity")
	count(_pf_ctlib_fields_named(s, "eventSource")) == 0
}
