package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cloudtrail-trail-data-resources-max", "ERROR", name,
	"Properties.EventSelectors",
	sprintf("the trail's event selectors hold %v data resource values in total; PutEventSelectors fails with \"Specify a valid number of DataResources.Values (0 to 250) for all your selectors\"", [n]),
	"Keep the total number of DataResources.Values across every event selector at 250 or fewer",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-cloudtrail-trail-dataresource.html") if {
	some name in resources_of_type("AWS::CloudTrail::Trail")
	n := _pf_ctlib_data_resource_value_total(name)
	n > 250
}
