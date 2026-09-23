package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-docdb-backup-window-format", "ERROR", name,
	"Properties.PreferredBackupWindow",
	sprintf("PreferredBackupWindow '%s' is not hh24:mi-hh24:mi (24H clock UTC); DocumentDB rejects it at create time (\"Should be specified as a time hh24:mi (24H Clock UTC). Example: 03:15\")", [w]),
	"Use the hh24:mi-hh24:mi form, e.g. 07:00-07:30",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbcluster.html") if {
	some name in _pf_docdb_clusters
	w := _pf_docdb_lit(name, "Properties.PreferredBackupWindow")
	not regex.match(`^([01][0-9]|2[0-3]):[0-5][0-9]-([01][0-9]|2[0-3]):[0-5][0-9]$`, w)
}
