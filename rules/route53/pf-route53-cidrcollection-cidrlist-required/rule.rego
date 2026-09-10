package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-cidrcollection-cidrlist-required", "ERROR", name,
	"Properties.Locations",
	sprintf("location %s has no CIDR blocks", [ln]),
	"Give the location its CIDR blocks, or drop the location",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-route53-cidrcollection.html") if {
	some name in resources_of_type("AWS::Route53::CidrCollection")
	some l in flatten_list(name, "Properties.Locations")
	is_object(l.value)
	ln := object.get(l.value, "LocationName", "")
	count(object.get(l.value, "CidrList", [])) == 0
}
