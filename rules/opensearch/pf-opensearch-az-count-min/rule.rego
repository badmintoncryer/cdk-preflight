package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-opensearch-az-count-min", "ERROR", name,
	"Properties.ClusterConfig.InstanceCount",
	sprintf("%v data nodes cannot cover %v Availability Zones; CreateDomain answers \"You must choose a minimum of three data nodes for a three Availability Zone deployment\"", [n, az]),
	"Raise InstanceCount to at least AvailabilityZoneCount (a multiple of it spreads the shards evenly)",
	"https://docs.aws.amazon.com/opensearch-service/latest/developerguide/managedomains-multiaz.html") if {
	some name in _pf_os_domains
	_pf_os_on(name, "ClusterConfig", "ZoneAwarenessEnabled")
	az := _pf_os_num(_pf_os_opt3(name, "ClusterConfig", "ZoneAwarenessConfig", "AvailabilityZoneCount"))
	n := _pf_os_num(_pf_os_opt(name, "ClusterConfig", "InstanceCount"))
	n < az
}
