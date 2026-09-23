package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-servicediscovery-public-namespace-name-pattern", "ERROR", name,
	"Properties.Name",
	"A public DNS namespace name must be a DNS domain name of at least two labels (a single label such as \"example\" is rejected)",
	"Use a registrable domain name such as example.com",
	"https://docs.aws.amazon.com/cloud-map/latest/api/API_CreatePublicDnsNamespace.html") if {
	some name in resources_of_type("AWS::ServiceDiscovery::PublicDnsNamespace")
	n := _pf_sd_str(name, "Name")
	not regex.match(`^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$`, n)
}
