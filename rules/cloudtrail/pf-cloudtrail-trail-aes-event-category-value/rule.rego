package cdk_preflight

import rego.v1

_pf_ctcatv_trail := {"Management", "Data", "NetworkActivity"}

violation contains make_diag_full("pf-cloudtrail-trail-aes-event-category-value", "ERROR", name,
	"Properties.AdvancedEventSelectors.FieldSelectors",
	sprintf("eventCategory '%v' is only valid on an event data store; a trail logs Management, Data or NetworkActivity", [v]),
	"Use Management, Data or NetworkActivity, or move the selector to an AWS::CloudTrail::EventDataStore",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-cloudtrail-trail-advancedfieldselector.html") if {
	some name in resources_of_type("AWS::CloudTrail::Trail")
	some s in _pf_ctlib_aes(name)
	some fs in _pf_ctlib_fields_named(s, "eventCategory")
	some v in _pf_ctlib_operator_values(fs, "Equals")
	not v in _pf_ctcatv_trail
}
