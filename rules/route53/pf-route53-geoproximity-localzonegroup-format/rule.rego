package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-geoproximity-localzonegroup-format", "ERROR", name,
	"Properties.GeoProximityLocation.LocalZoneGroup",
	sprintf("'%s' is not a Local Zone group name; Route 53 rejects it with \"Cannot find GeoProximityLocation with LocalZoneGroup\"", [lz]),
	"Use the Local Zone code without its trailing letter, for example us-west-2-den-1",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resource-record-sets-values-geoproximity.html") if {
	some name in resources_of_type("AWS::Route53::RecordSet")
	rs := _pf_r53lib_props(name)
	g := _pf_r53lib_get(rs, "GeoProximityLocation")
	is_object(g)
	lz := object.get(g, "LocalZoneGroup", null)
	is_string(lz)
	not regex.match("^[a-z]{2}-[a-z]+-[0-9]+-[a-z]+-[0-9]+$", lz)
}

violation contains make_diag_full("pf-route53-geoproximity-localzonegroup-format", "ERROR", name,
	sprintf("Properties.RecordSets[%d].GeoProximityLocation.LocalZoneGroup", [_pf_it.index]),
	sprintf("'%s' is not a Local Zone group name; Route 53 rejects it with \"Cannot find GeoProximityLocation with LocalZoneGroup\"", [lz]),
	"Use the Local Zone code without its trailing letter, for example us-west-2-den-1",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resource-record-sets-values-geoproximity.html") if {
	some name in resources_of_type("AWS::Route53::RecordSetGroup")
	some _pf_it in flatten_list(name, "Properties.RecordSets")
	rs := _pf_it.value
	is_object(rs)
	g := _pf_r53lib_get(rs, "GeoProximityLocation")
	is_object(g)
	lz := object.get(g, "LocalZoneGroup", null)
	is_string(lz)
	not regex.match("^[a-z]{2}-[a-z]+-[0-9]+-[a-z]+-[0-9]+$", lz)
}
