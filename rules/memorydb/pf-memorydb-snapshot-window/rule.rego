package cdk_preflight

import rego.v1

_pf_mdbsw_url := "https://docs.aws.amazon.com/memorydb/latest/APIReference/API_CreateCluster.html"

_pf_mdbsw_fix := "Write the snapshot window as hh24:mi-hh24:mi in UTC and keep it clear of MaintenanceWindow"

violation contains make_diag_full("pf-memorydb-snapshot-window", "ERROR", name,
	"Properties.SnapshotWindow",
	sprintf("'%s' is not hh24:mi-hh24:mi; CreateCluster fails with \"Invalid backup window format. Should be specified as a range hh24:mi-hh24:mi (24H Clock UTC)\"", [w]),
	_pf_mdbsw_fix, _pf_mdbsw_url) if {
	some name in resources_of_type("AWS::MemoryDB::Cluster")
	w := resolve(name, "Properties.SnapshotWindow")
	_pf_cachelib_lit(w)
	not _pf_cachelib_daily(w)
}

violation contains make_diag_full("pf-memorydb-snapshot-window", "ERROR", name,
	"Properties.SnapshotWindow",
	sprintf("snapshot window %s overlaps maintenance window %s; CreateCluster fails with \"The snapshot window and maintenance window must not overlap.\"", [sw, mw]),
	_pf_mdbsw_fix, _pf_mdbsw_url) if {
	some name in resources_of_type("AWS::MemoryDB::Cluster")
	sw := resolve(name, "Properties.SnapshotWindow")
	mw := resolve(name, "Properties.MaintenanceWindow")
	_pf_cachelib_overlap(mw, sw)
}
