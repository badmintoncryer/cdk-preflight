package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cloudtrail-trail-aes-data-requires-resources-type", "ERROR", name,
	"Properties.AdvancedEventSelectors.FieldSelectors",
	sprintf("advanced event selector %v logs eventCategory Data without a resources.type field; resources.type is required for data events", [i]),
	"Add {Field: resources.type, Equals: [<data event resource type>]} to the selector",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-cloudtrail-trail-advancedfieldselector.html") if {
	some name in resources_of_type("AWS::CloudTrail::Trail")
	some i, s in _pf_ctlib_aes(name)
	_pf_ctlib_category_is(s, "Data")
	count(_pf_ctlib_fields_named(s, "resources.type")) == 0
}
