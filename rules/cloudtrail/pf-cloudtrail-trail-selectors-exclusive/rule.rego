package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cloudtrail-trail-selectors-exclusive", "ERROR", name,
	"Properties.AdvancedEventSelectors",
	"the trail sets both EventSelectors and AdvancedEventSelectors; PutEventSelectors fails with \"You can select events by using either EventSelectors or AdvancedEventSelectors, but not both\"",
	"Keep one of the two: basic EventSelectors or AdvancedEventSelectors",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cloudtrail-trail.html") if {
	some name in resources_of_type("AWS::CloudTrail::Trail")
	count(_pf_ctlib_event_selectors(name)) > 0
	count(_pf_ctlib_aes(name)) > 0
}
