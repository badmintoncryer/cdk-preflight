package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-geolocation-subdivision-requires-us", "ERROR", name,
	"Properties.GeoLocation.SubdivisionCode",
	sprintf("SubdivisionCode '%s' is combined with CountryCode '%s'; Route 53 only knows subdivisions for the United States", [s, c]),
	"Set CountryCode to US, or drop SubdivisionCode and route on the country alone",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resource-record-sets-values-geo.html") if {
	some name in resources_of_type("AWS::Route53::RecordSet")
	rs := _pf_r53lib_props(name)
	g := _pf_r53lib_get(rs, "GeoLocation")
	is_object(g)
	s := object.get(g, "SubdivisionCode", null)
	is_string(s)
	c := object.get(g, "CountryCode", null)
	is_string(c)
	c != "US"
}

violation contains make_diag_full("pf-route53-geolocation-subdivision-requires-us", "ERROR", name,
	sprintf("Properties.RecordSets[%d].GeoLocation.SubdivisionCode", [_pf_it.index]),
	sprintf("SubdivisionCode '%s' is combined with CountryCode '%s'; Route 53 only knows subdivisions for the United States", [s, c]),
	"Set CountryCode to US, or drop SubdivisionCode and route on the country alone",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resource-record-sets-values-geo.html") if {
	some name in resources_of_type("AWS::Route53::RecordSetGroup")
	some _pf_it in flatten_list(name, "Properties.RecordSets")
	rs := _pf_it.value
	is_object(rs)
	g := _pf_r53lib_get(rs, "GeoLocation")
	is_object(g)
	s := object.get(g, "SubdivisionCode", null)
	is_string(s)
	c := object.get(g, "CountryCode", null)
	is_string(c)
	c != "US"
}
