package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-backup-advanced-setting-resource-type-ec2-only", "ERROR", name,
	sprintf("Properties.BackupPlan.AdvancedBackupSettings.%d.ResourceType", [a.index]),
	sprintf("AdvancedBackupSettings only configures Windows VSS for EC2, so ResourceType must be \"EC2\", got %v", [rt]),
	"Set ResourceType to EC2, or drop the advanced backup setting",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-backup-backupplan-advancedbackupsettingresourcetype.html") if {
	some name in resources_of_type("AWS::Backup::BackupPlan")
	some a in flatten_list(name, "Properties.BackupPlan.AdvancedBackupSettings")
	rt := _pf_bklib_str(a.value, "ResourceType")
	rt != "EC2"
}
