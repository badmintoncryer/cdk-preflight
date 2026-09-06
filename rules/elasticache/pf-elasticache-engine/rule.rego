package cdk_preflight

import rego.v1

_pf_eceng_url := "https://docs.aws.amazon.com/AmazonElastiCache/latest/APIReference/API_CreateReplicationGroup.html"

_pf_eceng_fix := "Use AWS::ElastiCache::CacheCluster for Memcached and AWS::ElastiCache::ReplicationGroup for Valkey"

violation contains make_diag_full("pf-elasticache-engine", "ERROR", name,
	"Properties.Engine",
	"a replication group cannot run Memcached; the create call fails with \"Specified engine does not support replication.\"",
	_pf_eceng_fix, _pf_eceng_url) if {
	some name in resources_of_type("AWS::ElastiCache::ReplicationGroup")
	lower(resolve(name, "Properties.Engine")) == "memcached"
}

violation contains make_diag_full("pf-elasticache-engine", "ERROR", name,
	"Properties.Engine",
	"AWS::ElastiCache::CacheCluster cannot run Valkey; the create call fails with \"This API doesn't support Valkey engine. Please use CreateReplicationGroup API for Valkey cluster creation.\"",
	_pf_eceng_fix, _pf_eceng_url) if {
	some name in resources_of_type("AWS::ElastiCache::CacheCluster")
	lower(resolve(name, "Properties.Engine")) == "valkey"
}
