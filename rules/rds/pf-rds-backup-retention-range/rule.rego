package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-rds-backup-retention-range", "ERROR", name,
	"Properties.BackupRetentionPeriod",
	sprintf("BackupRetentionPeriod %v exceeds the maximum; RDS rejects it with \"Retention period must be between 0 and 35.\"", [n]),
	"Use a retention period of 35 days or less",
	"https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_CreateDBInstance.html") if {
	some name in resources_of_type("AWS::RDS::DBInstance")
	n := to_number(resolve(name, "Properties.BackupRetentionPeriod"))
	n > 35
}
