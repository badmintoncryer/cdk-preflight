package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-backup-completion-window-gt-start-window", "ERROR", name,
	sprintf("Properties.BackupPlan.BackupPlanRule.%d.CompletionWindowMinutes", [r.index]),
	sprintf("CompletionWindowMinutes (%v) must be at least 60 minutes greater than StartWindowMinutes (%v)", [w, s]),
	"Set CompletionWindowMinutes to StartWindowMinutes + 60 or more",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-backup-backupplan-backupruleresourcetype.html") if {
	some name in resources_of_type("AWS::Backup::BackupPlan")
	some r in _pf_bklib_plan_rules(name)
	s := _pf_bklib_num(r.value, "StartWindowMinutes")
	w := _pf_bklib_num(r.value, "CompletionWindowMinutes")
	w < s + 60
}
