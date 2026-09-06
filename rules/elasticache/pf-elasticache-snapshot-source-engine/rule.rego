package cdk_preflight

import rego.v1

_pf_ecsse_url := "https://docs.aws.amazon.com/AmazonElastiCache/latest/APIReference/API_CreateCacheCluster.html"

_pf_ecsse_fix := "Restore from a snapshot only on a Redis cluster; Memcached has no snapshots"

violation contains make_diag_full("pf-elasticache-snapshot-source-engine", "ERROR", name,
	sprintf("Properties.%s", [key]),
	sprintf("%s is set on a Memcached cluster; the create call fails with \"Restoring a snapshot is not supported for this engine type\"", [key]),
	_pf_ecsse_fix, _pf_ecsse_url) if {
	some name in resources_of_type("AWS::ElastiCache::CacheCluster")
	lower(resolve(name, "Properties.Engine")) == "memcached"
	some key in ["SnapshotArns", "SnapshotName"]
	not _pf_cachelib_absent(name, key)
}
