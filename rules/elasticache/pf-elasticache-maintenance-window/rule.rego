package cdk_preflight

import rego.v1

_pf_ecmw_url := "https://docs.aws.amazon.com/AmazonElastiCache/latest/APIReference/API_CreateReplicationGroup.html"

_pf_ecmw_fix := "Write the window as ddd:hh24:mi-ddd:hh24:mi in UTC (e.g. sun:23:00-mon:01:30) and give it at least 60 minutes"

_pf_ecmw_types := ["AWS::ElastiCache::ReplicationGroup", "AWS::ElastiCache::CacheCluster"]

violation contains make_diag_full("pf-elasticache-maintenance-window", "ERROR", name,
	"Properties.PreferredMaintenanceWindow",
	sprintf("'%s' is not ddd:hh24:mi-ddd:hh24:mi; the create call fails with \"Invalid maintenance window format. Should be specified as a range ddd:hh24:mi-ddd:hh24:mi (24H Clock UTC)\"", [w]),
	_pf_ecmw_fix, _pf_ecmw_url) if {
	some t in _pf_ecmw_types
	some name in resources_of_type(t)
	w := resolve(name, "Properties.PreferredMaintenanceWindow")
	_pf_cachelib_lit(w)
	not _pf_cachelib_window(w)
}

violation contains make_diag_full("pf-elasticache-maintenance-window", "ERROR", name,
	"Properties.PreferredMaintenanceWindow",
	sprintf("the maintenance window '%s' is %d minutes long; the create call fails with \"Maintenance window must be at least 60 minutes.\"", [w, n]),
	_pf_ecmw_fix, _pf_ecmw_url) if {
	some t in _pf_ecmw_types
	some name in resources_of_type(t)
	w := resolve(name, "Properties.PreferredMaintenanceWindow")
	n := _pf_cachelib_window_minutes(w)
	n < 60
}
