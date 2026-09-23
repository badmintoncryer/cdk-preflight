package cdk_preflight

import rego.v1

_pf_nepmwd_types := {"AWS::Neptune::DBCluster", "AWS::Neptune::DBInstance"}

violation contains make_diag_full("pf-neptune-maintenance-window-duration", "ERROR", name,
	"Properties.PreferredMaintenanceWindow",
	sprintf("PreferredMaintenanceWindow '%s' spans only %v minutes; Neptune requires at least 30 (\"Maintenance window must be at least 30 minutes.\")", [w, d]),
	"Widen the maintenance window to 30 minutes or more",
	"https://docs.aws.amazon.com/neptune/latest/userguide/api-clusters.html") if {
	some t in _pf_nepmwd_types
	some name in resources_of_type(t)
	w := resolve(name, "Properties.PreferredMaintenanceWindow")
	is_string(w)
	p := split(w, "-")
	count(p) == 2
	s := _pf_neptunelib_wkmin(p[0])
	e := _pf_neptunelib_wkmin(p[1])
	d := ((e - s) + 10080) % 10080
	d < 30
}
