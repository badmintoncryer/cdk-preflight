package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-servicediscovery-service-dnsrecord-type-duplicate", "ERROR", name,
	"Properties.DnsConfig.DnsRecords",
	sprintf("A Cloud Map service may declare each DnsRecords type at most once, but this one repeats a type in %v", [types]),
	"Keep one entry per record type (a single TTL applies to the whole type)",
	"https://docs.aws.amazon.com/cloud-map/latest/api/API_DnsRecord.html") if {
	some name in resources_of_type("AWS::ServiceDiscovery::Service")
	types := _pf_sd_record_types(name)
	count(types) > count({t | some t in types})
}
