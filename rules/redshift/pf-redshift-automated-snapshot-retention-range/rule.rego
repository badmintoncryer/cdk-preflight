package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-redshift-automated-snapshot-retention-range", "ERROR", name,
	"Properties.AutomatedSnapshotRetentionPeriod",
	sprintf("AutomatedSnapshotRetentionPeriod %v exceeds 35; CreateCluster rejects it (\"Invalid automated snapshot retention period: %v. Retention period must be between 0 and 35.\")", [n, n]),
	"Use an automated snapshot retention period of 35 days or less",
	"https://docs.aws.amazon.com/redshift/latest/APIReference/API_CreateCluster.html") if {
	some name in resources_of_type("AWS::Redshift::Cluster")
	n := _pf_redshiftlib_num(name, "AutomatedSnapshotRetentionPeriod")
	n > 35
}
