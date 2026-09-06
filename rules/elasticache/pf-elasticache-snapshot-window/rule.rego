package cdk_preflight

import rego.v1

_pf_ecsw_url := "https://docs.aws.amazon.com/AmazonElastiCache/latest/APIReference/API_CreateReplicationGroup.html"

_pf_ecsw_fix := "Write the snapshot window as hh24:mi-hh24:mi in UTC (e.g. 05:00-09:00) and keep it clear of PreferredMaintenanceWindow"

_pf_ecsw_types := ["AWS::ElastiCache::ReplicationGroup", "AWS::ElastiCache::CacheCluster"]

violation contains make_diag_full("pf-elasticache-snapshot-window", "ERROR", name,
	"Properties.SnapshotWindow",
	sprintf("'%s' is not hh24:mi-hh24:mi; the create call fails with \"Invalid backup window format. Should be specified as a range hh24:mi-hh24:mi (24H Clock UTC)\"", [w]),
	_pf_ecsw_fix, _pf_ecsw_url) if {
	some t in _pf_ecsw_types
	some name in resources_of_type(t)
	w := resolve(name, "Properties.SnapshotWindow")
	_pf_cachelib_lit(w)
	not _pf_cachelib_daily(w)
}

# The snapshot window recurs daily, so it collides with a maintenance window
# that covers the same clock time on its day.
violation contains make_diag_full("pf-elasticache-snapshot-window", "ERROR", name,
	"Properties.SnapshotWindow",
	sprintf("snapshot window %s overlaps maintenance window %s; the create call fails with \"The snapshot window and maintenance window must not overlap.\"", [sw, mw]),
	_pf_ecsw_fix, _pf_ecsw_url) if {
	some t in _pf_ecsw_types
	some name in resources_of_type(t)
	sw := resolve(name, "Properties.SnapshotWindow")
	mw := resolve(name, "Properties.PreferredMaintenanceWindow")
	_pf_cachelib_overlap(mw, sw)
}
