package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-geolocation-duplicate-location", "ERROR", name,
	sprintf("Properties.RecordSets[%d]", [b.index]),
	sprintf("Two geolocation record sets for '%s' both cover %v; Route 53 keeps one record set per location", [k, g]),
	"Give each geolocation record set a different location, or merge them",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resource-record-sets-values-geo.html") if {
	some name in resources_of_type("AWS::Route53::RecordSetGroup")
	some a in flatten_list(name, "Properties.RecordSets")
	some b in flatten_list(name, "Properties.RecordSets")
	a.index < b.index
	k := _pf_r53lib_key(a.value)
	k == _pf_r53lib_key(b.value)
	g := _pf_r53lib_get(a.value, "GeoLocation")
	is_object(g)
	g == _pf_r53lib_get(b.value, "GeoLocation")
}
