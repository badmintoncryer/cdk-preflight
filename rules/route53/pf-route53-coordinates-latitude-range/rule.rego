package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-coordinates-latitude-range", "ERROR", name,
	"Properties.GeoProximityLocation.Coordinates.Latitude",
	sprintf("Latitude must be between -90 and 90, got %v", [n]),
	"Use a latitude in -90..90",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resource-record-sets-values-geoproximity.html") if {
	some name in resources_of_type("AWS::Route53::RecordSet")
	rs := _pf_r53lib_props(name)
	g := _pf_r53lib_get(rs, "GeoProximityLocation")
	is_object(g)
	c := object.get(g, "Coordinates", null)
	is_object(c)
	n := to_number(object.get(c, "Latitude", null))
	abs(n) > 90
}

violation contains make_diag_full("pf-route53-coordinates-latitude-range", "ERROR", name,
	sprintf("Properties.RecordSets[%d].GeoProximityLocation.Coordinates.Latitude", [_pf_it.index]),
	sprintf("Latitude must be between -90 and 90, got %v", [n]),
	"Use a latitude in -90..90",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resource-record-sets-values-geoproximity.html") if {
	some name in resources_of_type("AWS::Route53::RecordSetGroup")
	some _pf_it in flatten_list(name, "Properties.RecordSets")
	rs := _pf_it.value
	is_object(rs)
	g := _pf_r53lib_get(rs, "GeoProximityLocation")
	is_object(g)
	c := object.get(g, "Coordinates", null)
	is_object(c)
	n := to_number(object.get(c, "Latitude", null))
	abs(n) > 90
}
