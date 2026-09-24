package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cloudtrail-trail-aes-event-category-required", "ERROR", name,
	"Properties.AdvancedEventSelectors.FieldSelectors",
	sprintf("advanced event selector %v has no eventCategory field selector; CloudTrail requires eventCategory in every selector", [i]),
	"Add {Field: eventCategory, Equals: [Management | Data | NetworkActivity]} to the selector",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-cloudtrail-trail-advancedfieldselector.html") if {
	some name in resources_of_type("AWS::CloudTrail::Trail")
	some i, s in _pf_ctlib_aes(name)
	count(_pf_ctlib_fields_named(s, "eventCategory")) == 0
}
