package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-servicediscovery-service-dnsconfig-in-http-namespace", "ERROR", name,
	"Properties.DnsConfig",
	"An HTTP namespace publishes no DNS records, so a service created in one must not include a DnsConfig element",
	"Drop DnsConfig, or move the service to a public/private DNS namespace",
	"https://docs.aws.amazon.com/cloud-map/latest/api/API_CreateService.html") if {
	some name in resources_of_type("AWS::ServiceDiscovery::Service")
	_pf_sd_dnsconfig(name)
	some ns in _pf_sd_ns_ids(name)
	ns in resources_of_type("AWS::ServiceDiscovery::HttpNamespace")
}
