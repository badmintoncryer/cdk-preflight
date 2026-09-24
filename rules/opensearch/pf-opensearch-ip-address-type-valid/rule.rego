package cdk_preflight

import rego.v1

# Allowlist, hence WARN: the set is the enum CreateDomain printed on
# 2026-09-25, and a value AWS adds later would read as a violation. The same
# drift already happened to LogPublishingOptions (TASK_DETAILS_LOGS) and to
# TLSSecurityPolicy, whose documented sets were both short by one.
_pf_osip_known := {"ipv4", "dualstack"}

violation contains make_diag_full("pf-opensearch-ip-address-type-valid", "WARN", name,
	"Properties.IPAddressType",
	sprintf("IPAddressType \"%v\" is not one the service knows; CreateDomain answers \"Member must satisfy enum value set: [ipv4, dualstack]\"", [v]),
	"Use ipv4 or dualstack (dualstack is how a domain reaches IPv6 clients)",
	"https://docs.aws.amazon.com/opensearch-service/latest/APIReference/API_CreateDomain.html") if {
	some name in _pf_os_domains
	v := resolve(name, "Properties.IPAddressType")
	is_string(v)
	not v in _pf_osip_known
}
