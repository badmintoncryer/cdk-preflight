package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-servicediscovery-service-tcp-healthcheck-resourcepath", "ERROR", name,
	"Properties.HealthCheckConfig.ResourcePath",
	"A TCP health check only opens a connection, so HealthCheckConfig.ResourcePath must be omitted when Type is TCP",
	"Drop ResourcePath, or switch the health check Type to HTTP/HTTPS",
	"https://docs.aws.amazon.com/cloud-map/latest/api/API_HealthCheckConfig.html") if {
	some name in resources_of_type("AWS::ServiceDiscovery::Service")
	hc := _pf_sd_healthcheck(name)
	object.get(hc, "Type", "") == "TCP"
	object.get(hc, "ResourcePath", "__pf_absent") != "__pf_absent"
}
