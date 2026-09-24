package cdk_preflight

import rego.v1

# Allowlist, hence WARN: the set is the enum CreateDomain printed on
# 2026-09-24. The documentation still lists three of the five, so betting
# that a sixth cannot appear would be betting the same way twice.
_pf_ostls_known := {"Policy-Min-TLS-1-0-2019-07", "Policy-Min-TLS-1-2-2019-07", "Policy-Min-TLS-1-2-PFS-2023-10", "Policy-Min-TLS-1-2-RFC9151-FIPS-2024-08", "Policy-Min-TLS-1-2-FIPS-PQ-2026-10"}

violation contains make_diag_full("pf-opensearch-tls-policy-valid", "WARN", name,
	"Properties.DomainEndpointOptions.TLSSecurityPolicy",
	sprintf("\"%v\" is not a TLS policy the service knows; CreateDomain answers \"Member must satisfy enum value set: [Policy-Min-TLS-1-2-FIPS-PQ-2026-10, Policy-Min-TLS-1-0-2019-07, Policy-Min-TLS-1-2-2019-07, Policy-Min-TLS-1-2-RFC9151-FIPS-2024-08, Policy-Min-TLS-1-2-PFS-2023-10]\"", [p]),
	"Use Policy-Min-TLS-1-2-2019-07 or Policy-Min-TLS-1-2-PFS-2023-10",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-opensearchservice-domain-domainendpointoptions.html") if {
	some name in _pf_os_domains
	p := _pf_os_opt(name, "DomainEndpointOptions", "TLSSecurityPolicy")
	is_string(p)
	not p in _pf_ostls_known
}
