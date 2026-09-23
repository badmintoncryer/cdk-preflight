package cdk_preflight

import rego.v1

# 下限 1 は同梱エンジンのスキーマが F3034 で止める（2026-09-22 guard）ので、上限だけを見る。
violation contains make_diag_full("pf-neptune-backup-retention-range", "ERROR", name,
	"Properties.BackupRetentionPeriod",
	sprintf("BackupRetentionPeriod %v exceeds 35 days (\"Invalid backup retention period: 36. Retention period must be between 1 and 35.\")", [n]),
	"Use a retention period of 35 days or less",
	"https://docs.aws.amazon.com/neptune/latest/userguide/api-clusters.html") if {
	some name in resources_of_type("AWS::Neptune::DBCluster")
	n := to_number(resolve(name, "Properties.BackupRetentionPeriod"))
	n > 35
}
