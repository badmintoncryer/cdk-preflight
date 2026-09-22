package cdk_preflight

import rego.v1

_pf_dbesic_url := "https://docs.aws.amazon.com/documentdb/latest/developerguide/limits.html"

_pf_dbesic_fix := "Use at most 16 instances per shard (1 writer + up to 15 replicas)"

violation contains make_diag_full("pf-docdbelastic-shard-instance-count-max", "ERROR", name,
	"Properties.ShardInstanceCount",
	sprintf("ShardInstanceCount is %v; CreateCluster fails with \"Invalid Input - '%v'. ShardInstanceCount should be between 1 and 16.\"", [v, v]),
	_pf_dbesic_fix, _pf_dbesic_url) if {
	some name in resources_of_type("AWS::DocDBElastic::Cluster")
	v := to_number(resolve(name, "Properties.ShardInstanceCount"))
	v > 16
}
