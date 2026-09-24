package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-opensearch-fgac-requires-enforce-https", "ERROR", name,
	"Properties.DomainEndpointOptions.EnforceHTTPS",
	"fine-grained access control is on but the endpoint does not enforce HTTPS; CreateDomain answers \"You must enable EnforceHTTPS in the domain endpoint options to use advanced security.\"",
	"Set DomainEndpointOptions.EnforceHTTPS to true",
	"https://docs.aws.amazon.com/opensearch-service/latest/developerguide/fgac.html") if {
	some name in _pf_os_domains
	_pf_os_on(name, "AdvancedSecurityOptions", "Enabled")
	not _pf_os_on(name, "DomainEndpointOptions", "EnforceHTTPS")
}
