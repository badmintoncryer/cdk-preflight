package cdk_preflight

import rego.v1

_pf_dbesc_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdbelastic-cluster.html#cfn-docdbelastic-cluster-shardcapacity"

_pf_dbesc_fix := "Set ShardCapacity to one of 2, 4, 8, 16, 32 or 64 vCPUs"

_pf_dbesc_allowed := {2, 4, 8, 16, 32, 64}

violation contains make_diag_full("pf-docdbelastic-shard-capacity-enum", "ERROR", name,
	"Properties.ShardCapacity",
	sprintf("ShardCapacity is %v; CreateCluster fails with \"Invalid Input - '%v'. ShardCapacity must be a power of 2 within [2, 64].\"", [v, v]),
	_pf_dbesc_fix, _pf_dbesc_url) if {
	some name in resources_of_type("AWS::DocDBElastic::Cluster")
	v := to_number(resolve(name, "Properties.ShardCapacity"))
	not v in _pf_dbesc_allowed
}
