package cdk_preflight

import rego.v1

_pf_sdnr_no_dns_ns(name) if {
	object.get(_pf_sd_props(name), "DnsConfig", "__pf_absent") == "__pf_absent"
}

_pf_sdnr_no_dns_ns(name) if {
	dc := _pf_sd_dnsconfig(name)
	object.get(dc, "NamespaceId", "__pf_absent") == "__pf_absent"
}

violation contains make_diag_full("pf-servicediscovery-service-namespace-required", "ERROR", name,
	"Properties.NamespaceId",
	"A Cloud Map service must be created inside a namespace: set NamespaceId (CreateService rejects a service with no namespace id)",
	"Set NamespaceId to the namespace the service belongs to",
	"https://docs.aws.amazon.com/cloud-map/latest/api/API_CreateService.html") if {
	some name in resources_of_type("AWS::ServiceDiscovery::Service")
	props := input.resources[name].properties
	is_object(props)
	object.get(props, "NamespaceId", "__pf_absent") == "__pf_absent"
	_pf_sdnr_no_dns_ns(name)
}
