package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-servicediscovery-service-http-type-with-dnsconfig", "ERROR", name,
	"Properties.DnsConfig",
	"A service created with Type: HTTP is discoverable only through DiscoverInstances and creates no DNS records, so it must not include a DnsConfig element",
	"Drop Type: HTTP to publish DNS records, or drop DnsConfig to keep an API-only service",
	"https://docs.aws.amazon.com/cloud-map/latest/api/API_CreateService.html") if {
	some name in resources_of_type("AWS::ServiceDiscovery::Service")
	_pf_sd_str(name, "Type") == "HTTP"
	_pf_sd_dnsconfig(name)
}
