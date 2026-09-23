package cdk_preflight

import rego.v1

_pf_dbecnt_url := "https://docs.aws.amazon.com/documentdb/latest/developerguide/limits.html"

_pf_dbecnt_fix := "Use at most 32 shards (a hard quota, not adjustable); scale ShardCapacity instead"

violation contains make_diag_full("pf-docdbelastic-shard-count-max", "ERROR", name,
	"Properties.ShardCount",
	sprintf("ShardCount is %v; CreateCluster fails with \"Invalid Input - '%v'. ShardCount should be between 1 and 32.\"", [v, v]),
	_pf_dbecnt_fix, _pf_dbecnt_url) if {
	some name in resources_of_type("AWS::DocDBElastic::Cluster")
	v := to_number(resolve(name, "Properties.ShardCount"))
	v > 32
}
