package cdk_preflight

import rego.v1

_pf_bkcpy_vault_arn(s) if {
	parts := _pf_bklib_backup_arn(s)
	parts[5] == "backup-vault"
}

violation contains make_diag_full("pf-backup-copy-destination-vault-arn-format", "ERROR", name,
	sprintf("Properties.BackupPlan.BackupPlanRule.%d.CopyActions.%d.DestinationBackupVaultArn", [r.index, a.index]),
	sprintf("DestinationBackupVaultArn must be a backup vault ARN (arn:<partition>:backup:<region>:<account>:backup-vault:<name>), got %v", [arn]),
	"Use the vault ARN (CDK: vault.backupVaultArn), not a vault name or another resource ARN",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-backup-backupplan-copyactionresourcetype.html") if {
	some name in resources_of_type("AWS::Backup::BackupPlan")
	some r in _pf_bklib_plan_rules(name)
	some a in _pf_bklib_copy_actions(name, r.index)
	arn := _pf_bklib_str(a.value, "DestinationBackupVaultArn")
	not _pf_bkcpy_vault_arn(arn)
}
