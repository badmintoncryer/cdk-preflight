package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cloudtrail-trail-name-not-ip-format", "ERROR", name,
	"Properties.TrailName",
	sprintf("trail name '%v' is formatted as an IP address; CreateTrail fails with \"Trail names must not be formatted as an IP address\"", [t]),
	"Use a name that is not four dot-separated numbers",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cloudtrail-trail.html") if {
	some name in resources_of_type("AWS::CloudTrail::Trail")
	t := _pf_ctlib_str(name, "TrailName")
	regex.match("^[0-9]+[.][0-9]+[.][0-9]+[.][0-9]+$", t)
}
