package cdk_preflight

import rego.v1

# Denylist: list-instance-type-details answers WarmEnabled false for exactly
# t2.small, t2.medium, t3.small, t3.medium and the two ultrawarm1 types
# (us-east-1 2026-09-24) - which is both burstable families whole, since the
# catalog offers no other t2 or t3 size.
_pf_oswd_no_warm := {"t2", "t3"}

violation contains make_diag_full("pf-opensearch-warm-not-supported-on-data-type", "ERROR", name,
	"Properties.ClusterConfig.WarmEnabled",
	sprintf("UltraWarm on a %v data tier; CreateDomain answers \"Warm storage is not available for the %v instance type. Select a different instance type.\"", [t, t]),
	"Move the data tier to another family (m6g / r6g and the like), or drop the UltraWarm options",
	"https://docs.aws.amazon.com/opensearch-service/latest/developerguide/ultrawarm.html") if {
	some name in _pf_os_domains
	_pf_os_on(name, "ClusterConfig", "WarmEnabled")
	t := _pf_os_opt(name, "ClusterConfig", "InstanceType")
	_pf_os_family(t) in _pf_oswd_no_warm
}
