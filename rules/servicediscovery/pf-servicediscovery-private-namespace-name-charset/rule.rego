package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-servicediscovery-private-namespace-name-charset", "ERROR", name,
	"Properties.Name",
	"A private DNS namespace name must match ^(?!arn:)[!-~]{1,253}$: spaces, non-ASCII characters and a leading arn: are rejected",
	"Rename the namespace using printable ASCII characters only (no spaces)",
	"https://docs.aws.amazon.com/cloud-map/latest/api/API_CreatePrivateDnsNamespace.html") if {
	some name in resources_of_type("AWS::ServiceDiscovery::PrivateDnsNamespace")
	n := _pf_sd_str(name, "Name")
	not _pf_sd_printable_ascii(n)
}
