package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-docdb-restore-copy-on-write-time", "ERROR", name,
	"Properties.RestoreToTime",
	"RestoreToTime is set on a copy-on-write restore; DocumentDB rejects RestoreToTime when RestoreType is copy-on-write",
	"Drop RestoreToTime (a clone always uses the latest restorable time), or use RestoreType full-copy",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbcluster.html") if {
	some name in _pf_docdb_clusters
	rt := _pf_docdb_lit(name, "Properties.RestoreType")
	lower(rt) == "copy-on-write"
	_pf_docdb_has(name, "RestoreToTime")
}
