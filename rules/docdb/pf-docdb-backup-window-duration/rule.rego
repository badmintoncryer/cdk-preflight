package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-docdb-backup-window-duration", "ERROR", name,
	"Properties.PreferredBackupWindow",
	sprintf("PreferredBackupWindow '%s' is only %v minutes; DocumentDB requires at least 30 (\"Backup window must be at least 30 minutes.\")", [w, d]),
	"Widen the window to 30 minutes or more",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbcluster.html") if {
	some name in _pf_docdb_clusters
	w := _pf_docdb_lit(name, "Properties.PreferredBackupWindow")
	parts := split(w, "-")
	count(parts) == 2
	s := _pf_docdb_hm(parts[0])
	e := _pf_docdb_hm(parts[1])
	d := ((e - s) + 1440) % 1440
	d < 30
}
