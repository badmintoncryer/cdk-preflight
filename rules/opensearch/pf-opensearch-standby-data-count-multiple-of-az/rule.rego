package cdk_preflight

import rego.v1

# Only under standby. Without it the service takes an uneven spread: CreateDomain
# accepted 4 data nodes over 3 zone-aware AZs on 2026-09-24 (the domain was
# deleted before it finished building), so this stays gated on
# MultiAZWithStandbyEnabled - without it the only count rule is
# InstanceCount >= AvailabilityZoneCount.

violation contains make_diag_full("pf-opensearch-standby-data-count-multiple-of-az", "ERROR", name,
	"Properties.ClusterConfig.InstanceCount",
	sprintf("%v data nodes across %v Availability Zones; CreateDomain answers \"The number of data nodes must be a multiple of the number of Availability Zones configured for the domain.\"", [n, az]),
	"Set InstanceCount to a multiple of AvailabilityZoneCount",
	"https://docs.aws.amazon.com/opensearch-service/latest/developerguide/managedomains-multiaz.html") if {
	some name in _pf_os_domains
	_pf_os_on(name, "ClusterConfig", "MultiAZWithStandbyEnabled")
	az := _pf_os_num(_pf_os_opt3(name, "ClusterConfig", "ZoneAwarenessConfig", "AvailabilityZoneCount"))
	n := _pf_os_num(_pf_os_opt(name, "ClusterConfig", "InstanceCount"))
	n % az != 0
}
