package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-redshift-automated-snapshot-retention-ra3", "ERROR", name,
	"Properties.AutomatedSnapshotRetentionPeriod",
	sprintf("AutomatedSnapshotRetentionPeriod %v disables automated snapshots on node type %s; CreateCluster rejects it (\"You can't disable automated snapshots for RG or RA3 node types. Set the automated retention period from 1-35 days.\")", [n, nt]),
	"Set AutomatedSnapshotRetentionPeriod to a value from 1 to 35, or omit it (default 1)",
	"https://docs.aws.amazon.com/redshift/latest/APIReference/API_CreateCluster.html") if {
	some name in resources_of_type("AWS::Redshift::Cluster")
	_pf_redshiftlib_rms(name)
	nt := _pf_redshiftlib_node_type(name)
	n := _pf_redshiftlib_num(name, "AutomatedSnapshotRetentionPeriod")
	n < 1
}
