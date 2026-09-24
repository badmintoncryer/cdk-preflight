package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-opensearch-standby-requires-3-az", "ERROR", name,
	"Properties.ClusterConfig.ZoneAwarenessConfig.AvailabilityZoneCount",
	sprintf("standby over %v Availability Zones; CreateDomain answers \"Domains with standby must use 3 Availability Zones.\"", [az]),
	"Set AvailabilityZoneCount to 3, or drop MultiAZWithStandbyEnabled",
	"https://docs.aws.amazon.com/opensearch-service/latest/developerguide/managedomains-multiaz.html") if {
	some name in _pf_os_domains
	_pf_os_on(name, "ClusterConfig", "MultiAZWithStandbyEnabled")
	az := _pf_os_num(_pf_os_opt3(name, "ClusterConfig", "ZoneAwarenessConfig", "AvailabilityZoneCount"))
	az != 3
}
