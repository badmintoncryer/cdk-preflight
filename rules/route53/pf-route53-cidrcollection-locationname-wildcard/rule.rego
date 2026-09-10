package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-cidrcollection-locationname-wildcard", "ERROR", name,
	"Properties.Locations",
	"a location is named *, which Route 53 reserves for the default location every collection already has",
	"Name the location something else; records fall back to * on their own",
	"https://docs.aws.amazon.com/Route53/latest/APIReference/API_CreateCidrCollection.html") if {
	some name in resources_of_type("AWS::Route53::CidrCollection")
	some l in flatten_list(name, "Properties.Locations")
	is_object(l.value)
	object.get(l.value, "LocationName", "") == "*"
}
