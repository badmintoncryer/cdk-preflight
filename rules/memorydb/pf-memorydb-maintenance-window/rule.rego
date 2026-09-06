package cdk_preflight

import rego.v1

_pf_mdbmw_url := "https://docs.aws.amazon.com/memorydb/latest/APIReference/API_CreateCluster.html"

_pf_mdbmw_fix := "Write the window as ddd:hh24:mi-ddd:hh24:mi in UTC (e.g. sun:23:00-mon:01:30) and give it at least 60 minutes"

violation contains make_diag_full("pf-memorydb-maintenance-window", "ERROR", name,
	"Properties.MaintenanceWindow",
	sprintf("'%s' is not ddd:hh24:mi-ddd:hh24:mi; CreateCluster fails with \"Invalid maintenance window format. Should be specified as a range ddd:hh24:mi-ddd:hh24:mi (24H Clock UTC)\"", [w]),
	_pf_mdbmw_fix, _pf_mdbmw_url) if {
	some name in resources_of_type("AWS::MemoryDB::Cluster")
	w := resolve(name, "Properties.MaintenanceWindow")
	_pf_cachelib_lit(w)
	not _pf_cachelib_window(w)
}

violation contains make_diag_full("pf-memorydb-maintenance-window", "ERROR", name,
	"Properties.MaintenanceWindow",
	sprintf("the maintenance window '%s' is %d minutes long; CreateCluster fails with \"Maintenance window must be at least 60 minutes.\"", [w, n]),
	_pf_mdbmw_fix, _pf_mdbmw_url) if {
	some name in resources_of_type("AWS::MemoryDB::Cluster")
	w := resolve(name, "Properties.MaintenanceWindow")
	n := _pf_cachelib_window_minutes(w)
	n < 60
}
