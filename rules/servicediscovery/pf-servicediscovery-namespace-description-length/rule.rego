package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-servicediscovery-namespace-description-length", "ERROR", name,
	"Properties.Description",
	sprintf("A Cloud Map namespace description is limited to 1024 characters, but this one is %d", [count(d)]),
	"Shorten the description to 1024 characters or fewer",
	"https://docs.aws.amazon.com/cloud-map/latest/api/API_CreateHttpNamespace.html") if {
	some name in _pf_sd_namespaces
	d := _pf_sd_str(name, "Description")
	count(d) > 1024
}
