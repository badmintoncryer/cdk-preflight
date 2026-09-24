package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-backup-vault-lock-min-le-max-retention", "ERROR", name,
	"Properties.LockConfiguration.MinRetentionDays",
	sprintf("MinRetentionDays (%v) is above MaxRetentionDays (%v): the lock would reject every recovery point", [mn, mx]),
	"Set MinRetentionDays to MaxRetentionDays or less",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-backup-backupvault-lockconfigurationtype.html") if {
	some name in resources_of_type("AWS::Backup::BackupVault")
	lc := _pf_bklib_get(_pf_bklib_props(name), "LockConfiguration")
	mn := _pf_bklib_num(lc, "MinRetentionDays")
	mx := _pf_bklib_num(lc, "MaxRetentionDays")
	mn > mx
}
