package cdk_preflight

import rego.v1

_pf_ecaz_url := "https://docs.aws.amazon.com/AmazonElastiCache/latest/APIReference/API_CreateReplicationGroup.html"

_pf_ecaz_fix := "List one Availability Zone per node — the list length must equal NumCacheClusters (replication group) or NumCacheNodes (cluster)"

_pf_ecaz_table := [
	["AWS::ElastiCache::ReplicationGroup", "PreferredCacheClusterAZs", "NumCacheClusters"],
	["AWS::ElastiCache::CacheCluster", "PreferredAvailabilityZones", "NumCacheNodes"],
]

violation contains make_diag_full("pf-elasticache-preferred-availability-zones", "ERROR", name,
	sprintf("Properties.%s", [key]),
	sprintf("%d Availability Zones are listed for %v nodes; the create call fails with \"Must specify the same number of preferred availability zones as requested number of nodes\"", [count(azs), n]),
	_pf_ecaz_fix, _pf_ecaz_url) if {
	some [t, key, countKey] in _pf_ecaz_table
	some name in resources_of_type(t)
	azs := resolve(name, sprintf("Properties.%s", [key]))
	is_array(azs)
	n := to_number(resolve(name, sprintf("Properties.%s", [countKey])))
	count(azs) != n
}
