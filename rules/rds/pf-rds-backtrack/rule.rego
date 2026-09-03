package cdk_preflight

import rego.v1

_pf_rdsbt_url := "https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/AuroraMySQL.Managing.Backtrack.html"

violation contains make_diag_full("pf-rds-backtrack", "ERROR", name,
	"Properties.BacktrackWindow",
	sprintf("Backtrack is only available on aurora-mysql (\"Backtrack is not enabled for the %s engine.\")", [eng]),
	"Remove BacktrackWindow, or use the aurora-mysql engine",
	_pf_rdsbt_url) if {
	some name in resources_of_type("AWS::RDS::DBCluster")
	n := to_number(resolve(name, "Properties.BacktrackWindow"))
	n > 0
	eng := resolve(name, "Properties.Engine")
	is_string(eng)
	eng != "aurora-mysql"
}

violation contains make_diag_full("pf-rds-backtrack", "ERROR", name,
	"Properties.BacktrackWindow",
	sprintf("BacktrackWindow %v is outside 0-259200 seconds (72 hours)", [n]),
	"Use at most 259200 seconds",
	_pf_rdsbt_url) if {
	some name in resources_of_type("AWS::RDS::DBCluster")
	resolve(name, "Properties.Engine") == "aurora-mysql"
	n := to_number(resolve(name, "Properties.BacktrackWindow"))
	n > 259200
}
