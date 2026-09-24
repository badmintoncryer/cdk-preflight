package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-backup-start-window-minutes-min", "ERROR", name,
	sprintf("Properties.BackupPlan.BackupPlanRule.%d.StartWindowMinutes", [r.index]),
	sprintf("StartWindowMinutes must be at least 60 minutes, got %v", [s]),
	"Set StartWindowMinutes to 60 or more, or omit it to take the 60-minute default",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-backup-backupplan-backupruleresourcetype.html") if {
	some name in resources_of_type("AWS::Backup::BackupPlan")
	some r in _pf_bklib_plan_rules(name)
	s := _pf_bklib_num(r.value, "StartWindowMinutes")
	s < 60
}
