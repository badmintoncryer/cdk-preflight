package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-servicediscovery-instance-attribute-key-pattern", "ERROR", name,
	"Properties.InstanceAttributes",
	sprintf("Instance attribute key '%v' is not printable ASCII; RegisterInstance fails with \"Map keys must satisfy constraint: [... Member must satisfy regular expression pattern: ^[a-zA-Z0-9!-~]+$]\"", [k]),
	"Use printable ASCII with no spaces in the attribute key",
	"https://docs.aws.amazon.com/cloud-map/latest/api/API_RegisterInstance.html") if {
	some name in resources_of_type("AWS::ServiceDiscovery::Instance")
	some k, _ in _pf_sd_attrs(name)
	not regex.match(`^[a-zA-Z0-9!-~]+$`, k)
}
