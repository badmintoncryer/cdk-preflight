package cdk_preflight

import rego.v1

_pf_eccn_url := "https://docs.aws.amazon.com/AmazonElastiCache/latest/APIReference/API_CreateCacheCluster.html"

_pf_eccn_fix := "Keep NumCacheNodes at 1 for Redis (use a replication group for replicas), and give AZMode cross-az at least two nodes"

violation contains make_diag_full("pf-elasticache-cache-cluster-nodes", "ERROR", name,
	"Properties.NumCacheNodes",
	sprintf("a Redis cluster asks for %v nodes; the create call fails with \"Cannot create a Redis cluster with a NumCacheNodes parameter greater than 1.\"", [n]),
	_pf_eccn_fix, _pf_eccn_url) if {
	some name in resources_of_type("AWS::ElastiCache::CacheCluster")
	lower(resolve(name, "Properties.Engine")) == "redis"
	n := to_number(resolve(name, "Properties.NumCacheNodes"))
	n > 1
}

violation contains make_diag_full("pf-elasticache-cache-cluster-nodes", "ERROR", name,
	"Properties.AZMode",
	sprintf("AZMode is cross-az with %v node; the create call fails with \"Must specify at least two cache nodes in order to specify AZ Mode of 'cross-az'.\"", [n]),
	_pf_eccn_fix, _pf_eccn_url) if {
	some name in resources_of_type("AWS::ElastiCache::CacheCluster")
	resolve(name, "Properties.AZMode") == "cross-az"
	n := to_number(resolve(name, "Properties.NumCacheNodes"))
	n < 2
}
