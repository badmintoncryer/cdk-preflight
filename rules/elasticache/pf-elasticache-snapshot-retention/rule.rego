package cdk_preflight

import rego.v1

_pf_ecsr_url := "https://docs.aws.amazon.com/AmazonElastiCache/latest/APIReference/API_CreateReplicationGroup.html"

_pf_ecsr_fix := "Keep SnapshotRetentionLimit between 0 and 35, and drop it entirely on a Memcached cluster"

_pf_ecsr_types := ["AWS::ElastiCache::ReplicationGroup", "AWS::ElastiCache::CacheCluster"]

violation contains make_diag_full("pf-elasticache-snapshot-retention", "ERROR", name,
	"Properties.SnapshotRetentionLimit",
	sprintf("SnapshotRetentionLimit is %v; the create call fails with \"Invalid snapshot retention limit: %v. Retention limit must be between 0 and 35.\"", [v, v]),
	_pf_ecsr_fix, _pf_ecsr_url) if {
	some t in _pf_ecsr_types
	some name in resources_of_type(t)
	v := to_number(resolve(name, "Properties.SnapshotRetentionLimit"))
	_pf_ecsr_out_of_range(v)
}

_pf_ecsr_out_of_range(v) if v < 0

_pf_ecsr_out_of_range(v) if v > 35

violation contains make_diag_full("pf-elasticache-snapshot-retention", "ERROR", name,
	"Properties.SnapshotRetentionLimit",
	"the cluster runs Memcached, which has no snapshots; the create call fails with \"Engine does not support snapshotting. Snapshot retention limit parameter should not be specified.\"",
	_pf_ecsr_fix, _pf_ecsr_url) if {
	some name in resources_of_type("AWS::ElastiCache::CacheCluster")
	lower(resolve(name, "Properties.Engine")) == "memcached"
	not _pf_cachelib_absent(name, "SnapshotRetentionLimit")
}
