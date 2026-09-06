package cdk_preflight

import rego.v1

_pf_ecdt_url := "https://docs.aws.amazon.com/AmazonElastiCache/latest/APIReference/API_CreateReplicationGroup.html"

_pf_ecdt_fix := "Use an r6gd node type (cache.r6gd.xlarge and larger) for data tiering, or drop DataTieringEnabled"

violation contains make_diag_full("pf-elasticache-data-tiering-node-type", "ERROR", name,
	"Properties.DataTieringEnabled",
	sprintf("data tiering is enabled on node type %s; the create call fails with \"Data tiering is not supported for the node type %s.\"", [nt, nt]),
	_pf_ecdt_fix, _pf_ecdt_url) if {
	some name in resources_of_type("AWS::ElastiCache::ReplicationGroup")
	resolve(name, "Properties.DataTieringEnabled") == true
	nt := resolve(name, "Properties.CacheNodeType")
	_pf_cachelib_lit(nt)
	not _pf_cachelib_r6gd(nt)
}
