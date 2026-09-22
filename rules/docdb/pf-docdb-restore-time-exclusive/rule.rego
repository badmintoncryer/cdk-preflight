package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-docdb-restore-time-exclusive", "ERROR", name,
	"Properties.RestoreToTime",
	"RestoreToTime is set together with UseLatestRestorableTime: true; DocumentDB rejects the pair",
	"Keep only one of RestoreToTime and UseLatestRestorableTime",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbcluster.html") if {
	some name in _pf_docdb_clusters
	_pf_docdb_has(name, "RestoreToTime")
	_pf_docdb_true(name, "UseLatestRestorableTime")
}
