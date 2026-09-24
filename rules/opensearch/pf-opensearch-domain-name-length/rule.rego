package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-opensearch-domain-name-length", "ERROR", name,
	"Properties.DomainName",
	sprintf("DomainName is %v characters; CreateDomain answers \"Member must have length less than or equal to 28\"", [count(n)]),
	"Shorten the domain name to 28 characters or fewer",
	"https://docs.aws.amazon.com/opensearch-service/latest/APIReference/API_CreateDomain.html") if {
	some name in _pf_os_domains
	n := resolve(name, "Properties.DomainName")
	is_string(n)
	count(n) > 28
}
