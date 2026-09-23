package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-servicediscovery-instance-attribute-value-length", "ERROR", name,
	"Properties.InstanceAttributes",
	sprintf("Instance attribute '%v' has a %d character value; RegisterInstance fails with \"Map value must satisfy constraint: [Member must have length less than or equal to 1024 ...]\"", [k, count(v)]),
	"Use an attribute value of at most 1024 characters",
	"https://docs.aws.amazon.com/cloud-map/latest/api/API_RegisterInstance.html") if {
	some name in resources_of_type("AWS::ServiceDiscovery::Instance")
	some k, v in _pf_sd_attrs(name)
	is_string(v)
	count(v) > 1024
}
