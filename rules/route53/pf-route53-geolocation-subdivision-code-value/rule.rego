package cdk_preflight

import rego.v1

_pf_r53_ussub := {
	"AK", "AL", "AR", "AS", "AZ", "CA", "CO", "CT", "DC", "DE",
	"FL", "GA", "GU", "HI", "IA", "ID", "IL", "IN", "KS", "KY",
	"LA", "MA", "MD", "ME", "MI", "MN", "MO", "MP", "MS", "MT",
	"NC", "ND", "NE", "NH", "NJ", "NM", "NV", "NY", "OH", "OK",
	"OR", "PA", "PR", "RI", "SC", "SD", "TN", "TX", "UM", "UT",
	"VA", "VI", "VT", "WA", "WI", "WV", "WY",
}

violation contains make_diag_full("pf-route53-geolocation-subdivision-code-value", "ERROR", name,
	"Properties.GeoLocation.SubdivisionCode",
	sprintf("'%s' is not a US state or territory code; Route 53 rejects the record with \"Cannot find location\"", [s]),
	"Use the two-letter postal code of a US state, DC or a US territory",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resource-record-sets-values-geo.html") if {
	some name in resources_of_type("AWS::Route53::RecordSet")
	rs := _pf_r53lib_props(name)
	g := _pf_r53lib_get(rs, "GeoLocation")
	is_object(g)
	s := object.get(g, "SubdivisionCode", null)
	is_string(s)
	c := object.get(g, "CountryCode", null)
	is_string(c)
	c == "US"
	not s in _pf_r53_ussub
}

violation contains make_diag_full("pf-route53-geolocation-subdivision-code-value", "ERROR", name,
	sprintf("Properties.RecordSets[%d].GeoLocation.SubdivisionCode", [_pf_it.index]),
	sprintf("'%s' is not a US state or territory code; Route 53 rejects the record with \"Cannot find location\"", [s]),
	"Use the two-letter postal code of a US state, DC or a US territory",
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
	c == "US"
	not s in _pf_r53_ussub
}
