package cdk_preflight

import rego.v1

# Only the probed upper end is judged; -1 (indefinite) and the doc's lower end are left alone.
violation contains make_diag_full("pf-redshift-manual-snapshot-retention-range", "ERROR", name,
	"Properties.ManualSnapshotRetentionPeriod",
	sprintf("ManualSnapshotRetentionPeriod %v exceeds 3653 days; CreateCluster rejects it (\"Retention period cannot exceed 3653 days.\")", [n]),
	"Use a manual snapshot retention period of 3653 days or less, or -1 to retain indefinitely",
	"https://docs.aws.amazon.com/redshift/latest/APIReference/API_CreateCluster.html") if {
	some name in resources_of_type("AWS::Redshift::Cluster")
	n := _pf_redshiftlib_num(name, "ManualSnapshotRetentionPeriod")
	n > 3653
}
