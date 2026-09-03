package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-rds-backup-window-format", "ERROR", name,
	"Properties.PreferredBackupWindow",
	sprintf("PreferredBackupWindow '%s' is not hh24:mi-hh24:mi (24H clock UTC); RDS rejects it at create time", [w]),
	"Use the hh24:mi-hh24:mi form, e.g. 03:00-04:00",
	"https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_CreateDBInstance.html") if {
	some name in resources_of_type("AWS::RDS::DBInstance")
	w := resolve(name, "Properties.PreferredBackupWindow")
	is_string(w)
	not regex.match(`^([01][0-9]|2[0-3]):[0-5][0-9]-([01][0-9]|2[0-3]):[0-5][0-9]$`, w)
}
