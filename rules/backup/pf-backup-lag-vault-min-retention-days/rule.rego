package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-backup-lag-vault-min-retention-days", "ERROR", name,
	"Properties.MinRetentionDays",
	sprintf("MinRetentionDays %v is below the 7-day minimum a logically air-gapped vault accepts", [mn]),
	"Use a MinRetentionDays of 7 or more",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-backup-logicallyairgappedbackupvault.html") if {
	some name in resources_of_type("AWS::Backup::LogicallyAirGappedBackupVault")
	mn := _pf_bklib_num(_pf_bklib_props(name), "MinRetentionDays")
	mn < 7
}
