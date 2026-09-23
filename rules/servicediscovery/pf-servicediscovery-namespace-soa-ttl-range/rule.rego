package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-servicediscovery-namespace-soa-ttl-range", "ERROR", name,
	"Properties.Properties.DnsProperties.SOA.TTL",
	sprintf("The SOA record TTL of a Cloud Map DNS namespace must be between 0 and 2147483647 seconds, but it is %v", [ttl]),
	"Set the SOA TTL to 2147483647 seconds or fewer",
	"https://docs.aws.amazon.com/cloud-map/latest/api/API_SOA.html") if {
	some name in _pf_sd_dns_namespaces
	soa := object.get(object.get(object.get(_pf_sd_props(name), "Properties", {}), "DnsProperties", {}), "SOA", {})
	ttl := to_number(object.get(soa, "TTL", "__pf_absent"))
	ttl > 2147483647
}
