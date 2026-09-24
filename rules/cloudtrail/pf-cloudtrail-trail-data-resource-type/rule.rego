package cdk_preflight

import rego.v1

_pf_ctdrt_types := {"AWS::S3::Object", "AWS::Lambda::Function", "AWS::DynamoDB::Table"}

violation contains make_diag_full("pf-cloudtrail-trail-data-resource-type", "ERROR", name,
	"Properties.EventSelectors.DataResources.Type",
	sprintf("DataResources.Type '%v' is not one of AWS::S3::Object, AWS::Lambda::Function or AWS::DynamoDB::Table; PutEventSelectors fails with \"Value %v for DataResources.Type is invalid\"", [t, t]),
	"Use one of the three basic data resource types, or move the selector to AdvancedEventSelectors",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-cloudtrail-trail-dataresource.html") if {
	some name in resources_of_type("AWS::CloudTrail::Trail")
	some es in _pf_ctlib_event_selectors(name)
	some dr in _pf_ctlib_data_resources(es)
	t := object.get(dr, "Type", null)
	is_string(t)
	not t in _pf_ctdrt_types
}
