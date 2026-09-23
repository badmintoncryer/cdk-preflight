package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-servicediscovery-private-namespace-name-length", "ERROR", name,
	"Properties.Name",
	sprintf("A private DNS namespace name is limited to 253 characters, but this one is %d", [count(n)]),
	"Shorten the namespace name to 253 characters or fewer",
	"https://docs.aws.amazon.com/cloud-map/latest/api/API_CreatePrivateDnsNamespace.html") if {
	some name in resources_of_type("AWS::ServiceDiscovery::PrivateDnsNamespace")
	n := _pf_sd_str(name, "Name")
	count(n) > 253
}
