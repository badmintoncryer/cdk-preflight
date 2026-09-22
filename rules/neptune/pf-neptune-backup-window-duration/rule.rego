package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-neptune-backup-window-duration", "ERROR", name,
	"Properties.PreferredBackupWindow",
	sprintf("PreferredBackupWindow '%s' spans only %v minutes; Neptune requires at least 30 (\"Backup window must be at least 30 minutes.\")", [w, d]),
	"Widen the backup window to 30 minutes or more",
	"https://docs.aws.amazon.com/neptune/latest/userguide/api-clusters.html") if {
	some name in resources_of_type("AWS::Neptune::DBCluster")
	w := resolve(name, "Properties.PreferredBackupWindow")
	s := _pf_neptunelib_wstart(w)
	e := _pf_neptunelib_wend(w)
	d := ((e - s) + 1440) % 1440
	d < 30
}
