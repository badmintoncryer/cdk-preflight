package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-servicediscovery-service-cname-with-healthcheck", "ERROR", name,
	"Properties.HealthCheckConfig",
	"Cloud Map health checks are not supported for CNAME records; a service whose DnsRecords contain a CNAME must not declare HealthCheckConfig",
	"Drop HealthCheckConfig, or publish A/AAAA records instead of a CNAME",
	"https://docs.aws.amazon.com/cloud-map/latest/api/API_HealthCheckConfig.html") if {
	some name in resources_of_type("AWS::ServiceDiscovery::Service")
	"CNAME" in _pf_sd_record_types(name)
	_pf_sd_healthcheck(name)
}
