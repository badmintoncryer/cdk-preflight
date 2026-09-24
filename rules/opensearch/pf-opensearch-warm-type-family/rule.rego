package cdk_preflight

import rego.v1

# Allowlist, hence WARN: the 12 types CreateDomain printed on 2026-09-24.
# AWS adds UltraWarm sizes without touching the documentation, and an
# ERROR on a type added tomorrow would be a false positive.
_pf_oswt_known := {"ultrawarm1.medium.search", "ultrawarm1.large.search", "ultrawarm1.xlarge.search", "ultrawarm1.2xlarge.search", "oi2.large.search", "oi2.xlarge.search", "oi2.2xlarge.search", "oi2.4xlarge.search", "oi2.8xlarge.search", "oi2.12xlarge.search", "oi2.16xlarge.search", "oi2.24xlarge.search"}

violation contains make_diag_full("pf-opensearch-warm-type-family", "WARN", name,
	"Properties.ClusterConfig.WarmType",
	sprintf("\"%v\" is not an UltraWarm type; CreateDomain answers \"Member must satisfy enum value set: [ultrawarm1.xlarge.search, ultrawarm1.large.search, ultrawarm1.2xlarge.search, oi2.8xlarge.search, ...]\"", [t]),
	"Use ultrawarm1.medium.search / ultrawarm1.large.search or an oi2 type",
	"https://docs.aws.amazon.com/opensearch-service/latest/developerguide/ultrawarm.html") if {
	some name in _pf_os_domains
	t := _pf_os_opt(name, "ClusterConfig", "WarmType")
	is_string(t)
	not t in _pf_oswt_known
}
