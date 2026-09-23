package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-servicediscovery-service-name-case-collision", "ERROR", b,
	"Properties.Name",
	sprintf("DNS names are case-insensitive, so a DNS namespace cannot hold both %v and %v", [na, nb]),
	"Give the two services names that differ by more than letter case",
	"https://docs.aws.amazon.com/cloud-map/latest/api/API_CreateService.html") if {
	some a in resources_of_type("AWS::ServiceDiscovery::Service")
	some b in resources_of_type("AWS::ServiceDiscovery::Service")
	a < b
	na := _pf_sd_str(a, "Name")
	nb := _pf_sd_str(b, "Name")
	na != nb
	lower(na) == lower(nb)
	some ns in _pf_sd_ns_ids(a)
	ns in _pf_sd_ns_ids(b)
	ns in _pf_sd_dns_namespaces
}
