package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-servicediscovery-service-healthcheck-in-private-namespace", "ERROR", name,
	"Properties.HealthCheckConfig",
	"Route 53 health checks reach endpoints from the public internet, so HealthCheckConfig cannot be applied to a service in a private DNS namespace",
	"Drop HealthCheckConfig, or use HealthCheckCustomConfig for a private namespace",
	"https://docs.aws.amazon.com/cloud-map/latest/api/API_HealthCheckConfig.html") if {
	some name in resources_of_type("AWS::ServiceDiscovery::Service")
	_pf_sd_healthcheck(name)
	some ns in _pf_sd_ns_ids(name)
	ns in resources_of_type("AWS::ServiceDiscovery::PrivateDnsNamespace")
}
