package cdk_preflight

import rego.v1

_pf_ecport_url := "https://docs.aws.amazon.com/AmazonElastiCache/latest/APIReference/API_CreateReplicationGroup.html"

_pf_ecport_fix := "Pick a port in 1150-8004 or 8006-65535 (8005 is reserved)"

_pf_ecport_types := ["AWS::ElastiCache::ReplicationGroup", "AWS::ElastiCache::CacheCluster"]

violation contains make_diag_full("pf-elasticache-port", "ERROR", name,
	"Properties.Port",
	sprintf("Port %v is outside the accepted range; the create call fails with \"Invalid endpoint port: %v. Valid range is 1150-8004,8006-65535\"", [p, p]),
	_pf_ecport_fix, _pf_ecport_url) if {
	some t in _pf_ecport_types
	some name in resources_of_type(t)
	p := to_number(resolve(name, "Properties.Port"))
	not _pf_cachelib_port_ok(p)
}
