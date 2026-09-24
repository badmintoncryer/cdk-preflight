package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-backup-lag-vault-min-le-max-retention", "ERROR", name,
	"Properties.MinRetentionDays",
	sprintf("MinRetentionDays (%v) is above MaxRetentionDays (%v): the vault would reject every recovery point", [mn, mx]),
	"Set MinRetentionDays to MaxRetentionDays or less",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-backup-logicallyairgappedbackupvault.html") if {
	some name in resources_of_type("AWS::Backup::LogicallyAirGappedBackupVault")
	p := _pf_bklib_props(name)
	mn := _pf_bklib_num(p, "MinRetentionDays")
	mx := _pf_bklib_num(p, "MaxRetentionDays")
	mn > mx
}
