package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-docdb-maintenance-window-format", "ERROR", name,
	"Properties.PreferredMaintenanceWindow",
	sprintf("PreferredMaintenanceWindow '%s' is not ddd:hh24:mi-ddd:hh24:mi (24H clock UTC); DocumentDB rejects it at create time (\"Should be specified as a time ddd:hh24:mi (24H Clock UTC). Example: Mon:00:15\")", [w]),
	"Use the ddd:hh24:mi-ddd:hh24:mi form, e.g. mon:07:30-mon:08:00",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbcluster.html") if {
	some name in _pf_docdb_clusters
	w := _pf_docdb_lit(name, "Properties.PreferredMaintenanceWindow")
	not regex.match(`^(mon|tue|wed|thu|fri|sat|sun):([01][0-9]|2[0-3]):[0-5][0-9]-(mon|tue|wed|thu|fri|sat|sun):([01][0-9]|2[0-3]):[0-5][0-9]$`, lower(w))
}
