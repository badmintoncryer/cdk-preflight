package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-geolocation-continent-code-enum", "ERROR", name,
	"Properties.GeoLocation.ContinentCode",
	sprintf("'%s' is not a continent code; Route 53 rejects the record with \"Cannot find location\"", [c]),
	"Use AF, AN, AS, EU, OC, NA or SA",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resource-record-sets-values-geo.html") if {
	some name in resources_of_type("AWS::Route53::RecordSet")
	rs := _pf_r53lib_props(name)
	g := _pf_r53lib_get(rs, "GeoLocation")
	is_object(g)
	c := object.get(g, "ContinentCode", null)
	is_string(c)
	not c in {"AF", "AN", "AS", "EU", "OC", "NA", "SA"}
}

violation contains make_diag_full("pf-route53-geolocation-continent-code-enum", "ERROR", name,
	sprintf("Properties.RecordSets[%d].GeoLocation.ContinentCode", [_pf_it.index]),
	sprintf("'%s' is not a continent code; Route 53 rejects the record with \"Cannot find location\"", [c]),
	"Use AF, AN, AS, EU, OC, NA or SA",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resource-record-sets-values-geo.html") if {
	some name in resources_of_type("AWS::Route53::RecordSetGroup")
	some _pf_it in flatten_list(name, "Properties.RecordSets")
	rs := _pf_it.value
	is_object(rs)
	g := _pf_r53lib_get(rs, "GeoLocation")
	is_object(g)
	c := object.get(g, "ContinentCode", null)
	is_string(c)
	not c in {"AF", "AN", "AS", "EU", "OC", "NA", "SA"}
}
