package cdk_preflight

import rego.v1

# The limit is over every attribute, AWS_ ones included - keys plus values.
violation contains make_diag_full("pf-servicediscovery-instance-attributes-total-size", "ERROR", name,
	"Properties.InstanceAttributes",
	sprintf("The instance attributes add up to %d characters of keys and values; RegisterInstance fails with \"Instance attributes too large. Maximum allowed size of all attributes is 5000 characters.\"", [total]),
	"Keep the keys and values of all instance attributes within 5000 characters in total",
	"https://docs.aws.amazon.com/cloud-map/latest/api/API_RegisterInstance.html") if {
	some name in resources_of_type("AWS::ServiceDiscovery::Instance")
	total := sum([n |
		some k, v in _pf_sd_attrs(name)
		is_string(v)
		n := count(k) + count(v)
	])
	total > 5000
}
