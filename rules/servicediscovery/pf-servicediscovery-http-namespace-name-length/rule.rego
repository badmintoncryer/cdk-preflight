package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-servicediscovery-http-namespace-name-length", "ERROR", name,
	"Properties.Name",
	sprintf("An HTTP namespace name is limited to 1024 characters, but this one is %d", [count(n)]),
	"Shorten the namespace name to 1024 characters or fewer",
	"https://docs.aws.amazon.com/cloud-map/latest/api/API_CreateHttpNamespace.html") if {
	some name in resources_of_type("AWS::ServiceDiscovery::HttpNamespace")
	n := _pf_sd_str(name, "Name")
	count(n) > 1024
}
