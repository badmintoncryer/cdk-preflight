package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-servicediscovery-service-cname-requires-weighted", "ERROR", name,
	"Properties.DnsConfig.RoutingPolicy",
	"A service whose DnsRecords contain a CNAME must set RoutingPolicy to WEIGHTED; the default MULTIVALUE is rejected",
	"Set DnsConfig.RoutingPolicy to WEIGHTED, or use an A/AAAA record instead",
	"https://docs.aws.amazon.com/cloud-map/latest/api/API_DnsConfig.html") if {
	some name in resources_of_type("AWS::ServiceDiscovery::Service")
	"CNAME" in _pf_sd_record_types(name)
	_pf_sd_routing(name) != "WEIGHTED"
}
