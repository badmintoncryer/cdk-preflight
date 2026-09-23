package cdk_preflight

import rego.v1

# The 30 is counted over custom keys only; the AWS_ attributes are not part of it.
violation contains make_diag_full("pf-servicediscovery-instance-custom-attributes-max", "ERROR", name,
	"Properties.InstanceAttributes",
	sprintf("The instance carries %d custom attributes; RegisterInstance fails with \"Too many attributes provided: [...]. The current limit is 30\"", [count(custom)]),
	"Keep at most 30 custom attributes on an instance",
	"https://docs.aws.amazon.com/cloud-map/latest/api/API_RegisterInstance.html") if {
	some name in resources_of_type("AWS::ServiceDiscovery::Instance")
	custom := [k |
		some k, _ in _pf_sd_attrs(name)
		not startswith(upper(k), "AWS_")
	]
	count(custom) > 30
}
