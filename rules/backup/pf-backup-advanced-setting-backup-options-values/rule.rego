package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-backup-advanced-setting-backup-options-values", "ERROR", name,
	sprintf("Properties.BackupPlan.AdvancedBackupSettings.%d.BackupOptions.%s", [a.index, k]),
	sprintf("BackupOptions only accepts \"WindowsVSS\": \"enabled\" or \"disabled\", got %v: %v", [k, v]),
	"Use \"BackupOptions\": {\"WindowsVSS\": \"enabled\"} or {\"WindowsVSS\": \"disabled\"}",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-backup-backupplan-advancedbackupsettingresourcetype.html") if {
	some name in resources_of_type("AWS::Backup::BackupPlan")
	some a in flatten_list(name, "Properties.BackupPlan.AdvancedBackupSettings")
	bo := _pf_bklib_get(a.value, "BackupOptions")
	is_object(bo)
	some k, v in bo
	k == "WindowsVSS"
	not v in ["enabled", "disabled"]
}
