package cdk_preflight

import rego.v1

_pf_mdbrep_url := "https://docs.aws.amazon.com/memorydb/latest/APIReference/API_CreateCluster.html"

_pf_mdbrep_fix := "Keep NumReplicasPerShard between 0 and 5"

violation contains make_diag_full("pf-memorydb-replicas-per-shard", "ERROR", name,
	"Properties.NumReplicasPerShard",
	sprintf("NumReplicasPerShard is %v; CreateCluster fails with \"The number of replicas per shard must be within 0 and 5.\"", [v]),
	_pf_mdbrep_fix, _pf_mdbrep_url) if {
	some name in resources_of_type("AWS::MemoryDB::Cluster")
	v := to_number(resolve(name, "Properties.NumReplicasPerShard"))
	_pf_mdbrep_out_of_range(v)
}

_pf_mdbrep_out_of_range(v) if v < 0

_pf_mdbrep_out_of_range(v) if v > 5
