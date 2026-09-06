package cdk_preflight

import rego.v1

_pf_mdbeng_url := "https://docs.aws.amazon.com/memorydb/latest/APIReference/API_CreateCluster.html"

_pf_mdbeng_fix := "Leave Engine unset or set it to valkey / redis"

violation contains make_diag_full("pf-memorydb-engine", "ERROR", name,
	"Properties.Engine",
	sprintf("Engine is '%s'; CreateCluster fails with \"Specified engine does not support replication.\"", [e]),
	_pf_mdbeng_fix, _pf_mdbeng_url) if {
	some name in resources_of_type("AWS::MemoryDB::Cluster")
	e := resolve(name, "Properties.Engine")
	_pf_cachelib_lit(e)
	not lower(e) in {"valkey", "redis"}
}
