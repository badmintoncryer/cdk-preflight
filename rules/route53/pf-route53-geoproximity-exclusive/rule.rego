package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-geoproximity-exclusive", "ERROR", name,
	"Properties.GeoProximityLocation",
	sprintf("GeoProximityLocation specifies %d of AWSRegion / LocalZoneGroup / Coordinates; Route 53 expects exactly one", [count(set)]),
	"Keep one of AWSRegion, LocalZoneGroup or Coordinates",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resource-record-sets-values-geoproximity.html") if {
	some name in resources_of_type("AWS::Route53::RecordSet")
	rs := _pf_r53lib_props(name)
	g := _pf_r53lib_get(rs, "GeoProximityLocation")
	is_object(g)
	set := {k | some k in {"AWSRegion", "LocalZoneGroup", "Coordinates"}; object.get(g, k, "__pf_absent") != "__pf_absent"}
	count(set) > 1
}

violation contains make_diag_full("pf-route53-geoproximity-exclusive", "ERROR", name,
	sprintf("Properties.RecordSets[%d].GeoProximityLocation", [_pf_it.index]),
	sprintf("GeoProximityLocation specifies %d of AWSRegion / LocalZoneGroup / Coordinates; Route 53 expects exactly one", [count(set)]),
	"Keep one of AWSRegion, LocalZoneGroup or Coordinates",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resource-record-sets-values-geoproximity.html") if {
	some name in resources_of_type("AWS::Route53::RecordSetGroup")
	some _pf_it in flatten_list(name, "Properties.RecordSets")
	rs := _pf_it.value
	is_object(rs)
	g := _pf_r53lib_get(rs, "GeoProximityLocation")
	is_object(g)
	set := {k | some k in {"AWSRegion", "LocalZoneGroup", "Coordinates"}; object.get(g, k, "__pf_absent") != "__pf_absent"}
	count(set) > 1
}
