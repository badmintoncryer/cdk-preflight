package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-private-zone-health-check-policy", "ERROR", name,
	"Properties.HealthCheckId",
	"In a private hosted zone only failover, multivalue, weighted, latency, geolocation and geoproximity records may reference a health check",
	"Give the record a routing policy, or drop HealthCheckId",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/routing-policy.html") if {
	some name in resources_of_type("AWS::Route53::RecordSet")
	rs := _pf_r53lib_props(name)
	z := _pf_r53lib_own_zone(rs)
	_pf_r53lib_private_zone(z)
	_pf_r53lib_has(rs, "HealthCheckId")
	count(_pf_r53lib_kinds(rs)) == 0
}

violation contains make_diag_full("pf-route53-private-zone-health-check-policy", "ERROR", name,
	sprintf("Properties.RecordSets[%d].HealthCheckId", [_pf_it.index]),
	"In a private hosted zone only failover, multivalue, weighted, latency, geolocation and geoproximity records may reference a health check",
	"Give the record a routing policy, or drop HealthCheckId",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/routing-policy.html") if {
	some name in resources_of_type("AWS::Route53::RecordSetGroup")
	some _pf_it in flatten_list(name, "Properties.RecordSets")
	rs := _pf_it.value
	is_object(rs)
	z := _pf_r53lib_own_zone(rs)
	_pf_r53lib_private_zone(z)
	_pf_r53lib_has(rs, "HealthCheckId")
	count(_pf_r53lib_kinds(rs)) == 0
}
