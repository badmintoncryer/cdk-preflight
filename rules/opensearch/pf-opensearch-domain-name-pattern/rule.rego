package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-opensearch-domain-name-pattern", "ERROR", name,
	"Properties.DomainName",
	sprintf("DomainName \"%v\" does not match the service pattern [a-z][a-z0-9\\-]+; CreateDomain answers \"failed to satisfy constraint: Member must satisfy regular expression pattern\"", [n]),
	"Start the name with a lower-case letter and use only lower-case letters, digits and hyphens",
	"https://docs.aws.amazon.com/opensearch-service/latest/APIReference/API_CreateDomain.html") if {
	some name in _pf_os_domains
	n := resolve(name, "Properties.DomainName")
	is_string(n)
	not regex.match(`^[a-z][a-z0-9\-]+$`, n)
}
