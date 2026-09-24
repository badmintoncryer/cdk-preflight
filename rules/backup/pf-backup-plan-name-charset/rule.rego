package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-backup-plan-name-charset", "ERROR", name,
	"Properties.BackupPlan.BackupPlanName",
	sprintf("BackupPlanName %v contains characters other than alphanumerics, '-', '_' and '.'", [n]),
	"Rename the plan using alphanumerics and '-_.' only (no spaces)",
	"https://docs.aws.amazon.com/aws-backup/latest/devguide/API_BackupPlanInput.html") if {
	some name in resources_of_type("AWS::Backup::BackupPlan")
	bp := _pf_bklib_get(_pf_bklib_props(name), "BackupPlan")
	n := _pf_bklib_str(bp, "BackupPlanName")
	not _pf_bklib_dot_dash_name(n)
}
