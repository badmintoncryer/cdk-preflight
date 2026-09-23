package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-servicediscovery-service-attributes-max-entries", "ERROR", name,
	"Properties.ServiceAttributes",
	sprintf("A Cloud Map service may carry at most 30 service attributes, but this one declares %d", [count(a)]),
	"Keep at most 30 entries in ServiceAttributes",
	"https://docs.aws.amazon.com/cloud-map/latest/api/API_UpdateServiceAttributes.html") if {
	some name in resources_of_type("AWS::ServiceDiscovery::Service")
	a := object.get(_pf_sd_props(name), "ServiceAttributes", null)
	is_object(a)
	count(a) > 30
}
