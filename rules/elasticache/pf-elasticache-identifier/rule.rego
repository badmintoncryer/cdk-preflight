package cdk_preflight

import rego.v1

_pf_ecid_url := "https://docs.aws.amazon.com/AmazonElastiCache/latest/APIReference/API_CreateReplicationGroup.html"

_pf_ecid_fix := "Start the identifier with a letter, use letters, digits and single hyphens, and do not end with a hyphen"

_pf_ecid_table := [
	["AWS::ElastiCache::ReplicationGroup", "ReplicationGroupId", 40],
	["AWS::ElastiCache::CacheCluster", "ClusterName", 50],
]

violation contains make_diag_full("pf-elasticache-identifier", "ERROR", name,
	sprintf("Properties.%s", [key]),
	sprintf("'%s' is not a valid identifier; the create call fails with \"Identifiers must begin with a letter; must contain only ASCII letters, digits, and hyphens; and must not end with a hyphen or contain two consecutive hyphens\"", [v]),
	_pf_ecid_fix, _pf_ecid_url) if {
	some [t, key, _] in _pf_ecid_table
	some name in resources_of_type(t)
	v := resolve(name, sprintf("Properties.%s", [key]))
	_pf_cachelib_lit(v)
	not _pf_cachelib_identifier_ok(v)
}

violation contains make_diag_full("pf-elasticache-identifier", "ERROR", name,
	sprintf("Properties.%s", [key]),
	sprintf("'%s' is %d characters; the identifier is capped at %d", [v, count(v), cap]),
	_pf_ecid_fix, _pf_ecid_url) if {
	some [t, key, cap] in _pf_ecid_table
	some name in resources_of_type(t)
	v := resolve(name, sprintf("Properties.%s", [key]))
	_pf_cachelib_lit(v)
	count(v) > cap
}
