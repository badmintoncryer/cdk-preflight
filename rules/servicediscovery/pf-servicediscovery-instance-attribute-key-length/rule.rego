package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-servicediscovery-instance-attribute-key-length", "ERROR", name,
	"Properties.InstanceAttributes",
	sprintf("Instance attribute key is %d characters; RegisterInstance fails with \"Map keys must satisfy constraint: [Member must have length less than or equal to 255 ...]\"", [count(k)]),
	"Use an attribute key of at most 255 characters",
	"https://docs.aws.amazon.com/cloud-map/latest/api/API_RegisterInstance.html") if {
	some name in resources_of_type("AWS::ServiceDiscovery::Instance")
	some k, _ in _pf_sd_attrs(name)
	count(k) > 255
}
