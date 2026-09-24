package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-backup-vault-lock-changeable-for-days-min", "ERROR", name,
	"Properties.LockConfiguration.ChangeableForDays",
	sprintf("ChangeableForDays %v is below the 3-day minimum: AWS Backup enforces a 72-hour cooling-off period before a compliance-mode lock becomes immutable", [c]),
	"Use a ChangeableForDays of 3 or more, or omit it entirely for a governance-mode lock",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-backup-backupvault-lockconfigurationtype.html") if {
	some name in resources_of_type("AWS::Backup::BackupVault")
	lc := _pf_bklib_get(_pf_bklib_props(name), "LockConfiguration")
	c := _pf_bklib_num(lc, "ChangeableForDays")
	c < 3
}
