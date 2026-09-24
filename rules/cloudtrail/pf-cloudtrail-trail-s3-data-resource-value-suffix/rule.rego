package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cloudtrail-trail-s3-data-resource-value-suffix", "ERROR", name,
	"Properties.EventSelectors.DataResources.Values",
	sprintf("'%v' is a bucket ARN with no object path; PutEventSelectors fails with \"Value %v for DataResources.Values is invalid\"", [v, v]),
	"Append a trailing slash to log every object in the bucket (arn:aws:s3:::bucket/)",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-cloudtrail-trail-dataresource.html") if {
	some name in resources_of_type("AWS::CloudTrail::Trail")
	some es in _pf_ctlib_event_selectors(name)
	some dr in _pf_ctlib_data_resources(es)
	object.get(dr, "Type", null) == "AWS::S3::Object"
	some v in _pf_ctlib_data_resource_values(dr)
	is_string(v)
	regex.match("^arn:aws[a-z-]*:s3:::[^/]+$", v)
}
