package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cloudtrail-trail-name-adjacent-separators", "ERROR", name,
	"Properties.TrailName",
	sprintf("trail name '%v' has two adjacent separators; CreateTrail fails with \"Trail name or ARN cannot have adjacent periods (.), hyphens (-), or underscores (_)\"", [t]),
	"Use single separators between the name's segments",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cloudtrail-trail.html") if {
	some name in resources_of_type("AWS::CloudTrail::Trail")
	t := _pf_ctlib_str(name, "TrailName")
	regex.match("[._-][._-]", t)
}
