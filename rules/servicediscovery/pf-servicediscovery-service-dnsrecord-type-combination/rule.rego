package cdk_preflight

import rego.v1

_pf_sdrtc_ok(types) if {
	some allowed in [{"A"}, {"AAAA"}, {"A", "AAAA"}, {"SRV"}, {"CNAME"}]
	types == allowed
}

violation contains make_diag_full("pf-servicediscovery-service-dnsrecord-type-combination", "ERROR", name,
	"Properties.DnsConfig.DnsRecords",
	sprintf("A Cloud Map service may only combine DnsRecords types as {A}, {AAAA}, {A, AAAA}, {SRV} or {CNAME}, but this one declares %v", [types]),
	"Split the records across services, or keep only A and AAAA together",
	"https://docs.aws.amazon.com/cloud-map/latest/api/API_DnsRecord.html") if {
	some name in resources_of_type("AWS::ServiceDiscovery::Service")
	types := {t | some t in _pf_sd_record_types(name)}
	count(types) > 0
	not _pf_sdrtc_ok(types)
}
