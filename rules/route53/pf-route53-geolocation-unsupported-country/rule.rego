package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-geolocation-unsupported-country", "ERROR", name,
	"Properties.GeoLocation.CountryCode",
	sprintf("Route 53 has no geolocation data for '%s' (Bouvet Island, Christmas Island, Western Sahara and Heard & McDonald Islands are rejected with \"Cannot find location\")", [c]),
	"Cover these visitors with a continent-level or default ('*') record instead",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resource-record-sets-values-geo.html") if {
	some name in resources_of_type("AWS::Route53::RecordSet")
	rs := _pf_r53lib_props(name)
	g := _pf_r53lib_get(rs, "GeoLocation")
	is_object(g)
	c := object.get(g, "CountryCode", null)
	is_string(c)
	c in {"BV", "CX", "EH", "HM"}
}

violation contains make_diag_full("pf-route53-geolocation-unsupported-country", "ERROR", name,
	sprintf("Properties.RecordSets[%d].GeoLocation.CountryCode", [_pf_it.index]),
	sprintf("Route 53 has no geolocation data for '%s' (Bouvet Island, Christmas Island, Western Sahara and Heard & McDonald Islands are rejected with \"Cannot find location\")", [c]),
	"Cover these visitors with a continent-level or default ('*') record instead",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resource-record-sets-values-geo.html") if {
	some name in resources_of_type("AWS::Route53::RecordSetGroup")
	some _pf_it in flatten_list(name, "Properties.RecordSets")
	rs := _pf_it.value
	is_object(rs)
	g := _pf_r53lib_get(rs, "GeoLocation")
	is_object(g)
	c := object.get(g, "CountryCode", null)
	is_string(c)
	c in {"BV", "CX", "EH", "HM"}
}
