package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-servicediscovery-http-namespace-name-charset", "ERROR", name,
	"Properties.Name",
	"An HTTP namespace name must match ^(?!arn:)[!-~]{1,1024}$: spaces, non-ASCII characters and a leading arn: are rejected",
	"Rename the namespace using printable ASCII characters only (no spaces)",
	"https://docs.aws.amazon.com/cloud-map/latest/api/API_CreateHttpNamespace.html") if {
	some name in resources_of_type("AWS::ServiceDiscovery::HttpNamespace")
	n := _pf_sd_str(name, "Name")
	not _pf_sd_printable_ascii(n)
}
