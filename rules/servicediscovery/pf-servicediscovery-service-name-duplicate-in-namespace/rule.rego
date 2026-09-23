package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-servicediscovery-service-name-duplicate-in-namespace", "ERROR", b,
	"Properties.Name",
	sprintf("A Cloud Map namespace cannot hold two services named %v", [na]),
	"Rename one of the services, or point it at a different namespace",
	"https://docs.aws.amazon.com/cloud-map/latest/api/API_CreateService.html") if {
	some a in resources_of_type("AWS::ServiceDiscovery::Service")
	some b in resources_of_type("AWS::ServiceDiscovery::Service")
	a < b
	na := _pf_sd_str(a, "Name")
	na == _pf_sd_str(b, "Name")
	some ns in _pf_sd_ns_ids(a)
	ns in _pf_sd_ns_ids(b)
}
