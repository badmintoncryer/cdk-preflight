package cdk_preflight

import rego.v1

_pf_mdbsr_url := "https://docs.aws.amazon.com/memorydb/latest/APIReference/API_CreateCluster.html"

_pf_mdbsr_fix := "Keep SnapshotRetentionLimit between 0 and 35 days"

violation contains make_diag_full("pf-memorydb-snapshot-retention", "ERROR", name,
	"Properties.SnapshotRetentionLimit",
	sprintf("SnapshotRetentionLimit is %v; CreateCluster fails with \"Invalid snapshot retention limit: %v. Retention limit must be between 0 and 35.\"", [v, v]),
	_pf_mdbsr_fix, _pf_mdbsr_url) if {
	some name in resources_of_type("AWS::MemoryDB::Cluster")
	v := to_number(resolve(name, "Properties.SnapshotRetentionLimit"))
	_pf_mdbsr_out_of_range(v)
}

_pf_mdbsr_out_of_range(v) if v < 0

_pf_mdbsr_out_of_range(v) if v > 35
